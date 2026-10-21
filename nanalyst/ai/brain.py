"""The AI analyst "brain": a reasoning client the engine uses to REASON and DECIDE during analysis.

Backend: any OpenAI-compatible chat API (OpenAI, a local server, or another vendor's compatible
endpoint via base_url). Keys resolve from env vars first, then from an analyst config file
([openai] api_key + optional base_url, plus [openai_pool] key1..keyN for rate-limit rotation).
Config is searched at $NANALYST_CONFIG, the repo root and the cwd.

Design contract (unchanged):
  * AUGMENTATION, not dependency — no key/SDK => `available` is False and every method
    returns None, so callers fall back to the deterministic path.
  * The brain decides WHAT to do and narrates; it NEVER produces the maliciousness SCORE
    (that stays deterministic + evidence-gated in proof.py) so it can't inflate a verdict.
  * Secrets are never logged.
"""
from __future__ import annotations

import configparser
import json
import os
import re
from pathlib import Path

DEFAULT_MODEL = os.environ.get("NANALYST_MODEL", "gpt-4o")

_CONFIG_PATHS = [
    os.environ.get("NANALYST_CONFIG", ""),
    str(Path(__file__).resolve().parents[2] / "kali_config.ini"),   # analyst repo root
    str(Path.cwd() / "kali_config.ini"),
    str(Path.home() / ".nemesis-analyst" / "config.ini"),
]


def _load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    for p in _CONFIG_PATHS:
        if p and Path(p).exists():
            try:
                cfg.read(p)
                break
            except Exception:
                continue
    return cfg


def _extract_json(text: str):
    """Pull the first JSON object/array out of a model reply (tolerates prose/fences)."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", t).strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    for open_c, close_c in (("{", "}"), ("[", "]")):
        i = t.find(open_c)
        if i < 0:
            continue
        depth = 0
        for j in range(i, len(t)):
            if t[j] == open_c:
                depth += 1
            elif t[j] == close_c:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[i:j + 1])
                    except Exception:
                        break
    return None


class Brain:
    def __init__(self, provider: str | None = None, model: str | None = None, log=print,
                 transcript=None):
        self.log = log
        self.transcript = transcript      # optional fn(dict) — records every request/response
        self.calls = 0
        self.last_error = None
        self._client = None
        self._kind = None                 # "openai" when a client is up
        self._keys: list[str] = []        # for key-pool rotation
        self._key_idx = 0

        cfg = _load_config()
        self._base_url = (os.environ.get("OPENAI_BASE_URL")
                          or (cfg.get("openai", "base_url").strip()
                              if cfg.has_option("openai", "base_url") else None))
        keys = self._openai_keys(cfg)
        if keys:
            self._init_openai(keys, model)

    # ---- key resolution (never logged) ----
    @staticmethod
    def _openai_keys(cfg) -> list[str]:
        keys = []
        if os.environ.get("OPENAI_API_KEY"):
            keys.append(os.environ["OPENAI_API_KEY"])
        if cfg.has_option("openai", "api_key"):
            keys.append(cfg.get("openai", "api_key").strip())
        if cfg.has_section("openai_pool"):
            for k, v in cfg.items("openai_pool"):
                if k.startswith("key") and v.strip():
                    keys.append(v.strip())
        # de-dup, keep order
        seen, out = set(), []
        for k in keys:
            if k and k not in seen:
                seen.add(k); out.append(k)
        return out

    def _init_openai(self, keys, model):
        try:
            import openai  # noqa
            self._keys = keys
            self._kind = "openai"
            self.model = model or DEFAULT_MODEL
            self._build_openai_client()
        except Exception as exc:
            self.last_error = f"openai init failed: {exc}"
            self.log(f"[ai] {self.last_error}")

    def _build_openai_client(self):
        import openai
        kw = {"api_key": self._keys[self._key_idx]}
        if self._base_url:
            kw["base_url"] = self._base_url
        self._client = openai.OpenAI(**kw)

    @property
    def available(self) -> bool:
        return self._client is not None

    @property
    def provider(self) -> str:
        return f"{self._kind}:{getattr(self, 'model', '?')}" if self._kind else "none"

    def _rotate_openai(self) -> bool:
        """Advance to the next pool key after a rate-limit/auth failure. Returns True
        if another key is available."""
        if self._kind != "openai" or self._key_idx + 1 >= len(self._keys):
            return False
        self._key_idx += 1
        self._build_openai_client()
        self.log(f"[ai] rotated to OpenAI pool key #{self._key_idx + 1}/{len(self._keys)}")
        return True

    def _record(self, purpose, system, user, response, error, ms):
        """Log every AI request/response — concise line + full transcript + audit ledger."""
        tag = purpose or "ai"
        if error:
            self.log(f"[ai] {tag}: ERROR after {ms}ms — {error}")
        else:
            self.log(f"[ai] {tag}: {self._kind}/{self.model} key#{self._key_idx+1} "
                     f"-> {len(response or '')} chars in {ms}ms")
        rec = {"purpose": purpose, "provider": self._kind, "model": self.model,
               "key_index": self._key_idx + 1, "prompt_chars": len(system) + len(user),
               "system": system, "user": user, "response": response,
               "error": error, "latency_ms": ms}
        if self.transcript:
            try:
                self.transcript(rec)
            except Exception:
                pass

    # ---- unified completion ----
    def ask(self, system: str, user: str, max_tokens: int = 2000,
            temperature: float = 0.0, model: str | None = None, purpose: str = "") -> str | None:
        if not self.available:
            return None
        import time
        mdl = model or self.model
        t0 = time.time()
        for _attempt in range(max(len(self._keys), 1)):
            try:
                self.calls += 1
                r = self._client.chat.completions.create(
                    model=mdl, max_tokens=max_tokens, temperature=temperature,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}])
                out = (r.choices[0].message.content or "").strip()
                self._record(purpose, system, user, out, None, int((time.time() - t0) * 1000))
                return out
            except Exception as exc:
                self.last_error = str(exc)
                name = type(exc).__name__
                msg = str(exc).lower()
                rotatable = ("RateLimit" in name or "Authentication" in name
                             or "PermissionDenied" in name
                             or any(w in msg for w in ("quota", "billing", "insufficient",
                                                       "exceeded", "payment")))
                if rotatable and self._rotate_openai():
                    continue
                self._record(purpose, system, user, None, f"{name}: {exc}",
                             int((time.time() - t0) * 1000))
                return None
        return None

    def decide(self, system: str, user: str, max_tokens: int = 1500,
               model: str | None = None, purpose: str = ""):
        """Ask for a single JSON decision and parse it. Returns dict/list or None."""
        txt = self.ask(system + "\n\nRespond with ONLY a JSON object (no prose, no code fences).",
                       user, max_tokens=max_tokens, model=model, purpose=purpose)
        return _extract_json(txt) if txt else None
