"""Detection package: analysis output that security vendors can consume directly.

One folder per analysis (`intel/`):
  iocs.json    every indicator with provenance, confidence tier and intended use; plus the
               indicators that were FILTERED OUT and why; plus what is NOT available and why
  iocs.csv     the same, flat (type,value,usage,confidence,tier,sources,context)
  hashes.txt   sha256 / sha1 / md5 / imphash of the sample, every unpacked payload and dropped file
  yara/*.yar   one rule per stage (packed / unpacked / decrypted); WITHHELD, with a reason, when
               there are too few distinctive strings to avoid a noisy rule
  suricata.rules   DNS / IP / HTTP rules, ONLY from indicators observed or recovered (tier >= 70)
  sigma/*.yml  host-behaviour rules, ONLY where the analysis produced the evidence
  stix.json    STIX 2.1 bundle (indicators, malware, relationships), TLP-marked
  README.md    what each file is, how far to trust it, known limits

Trust rules (vendors drop feeds that cry wolf):
  * every indicator has a tier: observed (on the wire / live) > decrypted/unpacked (recovered from
    the payload) > static (strings of the packed file) > ai (suggested, unverified; never emitted
    as a rule);
  * known-good values (Microsoft/CA/standards domains, private or reserved IPs, version numbers
    that look like IPs) are filtered and listed under `excluded` with the reason;
  * network rules only from tier >= 70.
Producer is the organisation name only (no personal contact details).
"""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

PRODUCER = "Nemesis Labs"
NS = uuid.UUID("6f1d2b2e-5a54-4b5e-9d0e-7a1c8f3b2a10")        # fixed namespace -> reproducible IDs
TIER_SCORE = {"observed": 90, "decrypted": 80, "unpacked": 70, "static": 40, "ai": 20}
RULE_MIN_TIER = 70

_SRC_TIER = [("live detonation (network)", "observed"), ("live detonation", "decrypted"),
             ("deep static (decrypted)", "decrypted"), ("API-trace region dump", "unpacked"),
             ("AI-plan watch region", "unpacked"), ("memory dump", "unpacked"), ("reconstructed PE", "unpacked"),
             ("deep static (unpacked)", "unpacked"), ("recovered source", "unpacked"),
             ("deep static (packed)", "static"), ("static", "static")]

GOOD_DOMAINS = ("microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "office365.com",
                "msn.com", "bing.com", "msftncsi.com", "msftconnecttest.com", "azure.com", "azureedge.net",
                "digicert.com", "verisign.com", "symantec.com", "entrust.net", "globalsign.com", "godaddy.com",
                "letsencrypt.org", "lencr.org", "sectigo.com", "usertrust.com", "w3.org", "xmlsoap.org",
                "mozilla.org", "mozilla.com", "google.com", "gstatic.com", "googleapis.com", "apple.com",
                "openssl.org", "python.org", "adobe.com", "oracle.com", "java.com", "mcafee.com", "avast.com")
HOST_CMD = re.compile(r"(?i)(vssadmin[^\n]{0,40}delete|shadowcopy|bcdedit[^\n]{0,60}(recoveryenabled|bootstatuspolicy)|"
                      r"wbadmin[^\n]{0,30}delete|wmic[^\n]{0,30}shadowcopy|powershell[^\n]{0,30}-e(nc|ncodedcommand)|"
                      r"schtasks[^\n]{0,20}/create|reg(?:\.exe)?\s+add[^\n]{0,80}\\run|certutil[^\n]{0,30}urlcache|"
                      r"bitsadmin[^\n]{0,30}/transfer|cipher\s+/w|mshta\s+http|rundll32[^\n]{0,40}javascript)")
NOTE_NAME = re.compile(r"(?i)(_RECOVERY_|HOW[_ ]TO|DECRYPT|RESTORE[_ ]FILES|READ[_ ]?ME[_ ]?(FOR|TO)?[_ ]?(DECRYPT|RESTORE)|"
                       r"YOUR[_ ]FILES|HELP[_ ](RESTORE|DECRYPT)|RECOVER[Y_ ]?(INSTRUCTION|KEY|FILE))")
USER_PATH = re.compile(r"(?i)\\(AppData|Temp|ProgramData|Users\\Public|Downloads)\\")

_MAL = {"ransomware": "ransomware", "keylogger": "keylogger", "infostealer": "spyware", "bot": "bot",
        "banker": "trojan", "dropper": "dropper", "worm": "worm", "injector": "trojan", "loader/packer": "trojan"}


# ----------------------------------------------------------------------------- filters
def _good_domain(d: str) -> bool:
    d = d.lower().strip(".")
    return any(d == g or d.endswith("." + g) for g in GOOD_DOMAINS)


def filter_ip(v: str):
    """(keep, reason). Drops private/reserved addresses and version numbers that look like IPs."""
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False, "not a valid IP address"
    if not ip.is_global:
        return False, "private/reserved/loopback address"
    o = [int(x) for x in v.split(".")] if ip.version == 4 else []
    if o and (o[2:] == [0, 0] or (o[3] == 0 and o[0] < 20)):
        return False, "looks like a version number, not an address"
    return True, ""


def filter_domain(v: str):
    d = v.lower().strip(".")
    if "." not in d or len(d) < 4:
        return False, "too short / not a domain"
    if _good_domain(d):
        return False, "known-good domain (vendor/CA/standards)"
    if re.search(r"\.(dll|exe|sys|dat|tmp|log|txt|bin)$", d):
        return False, "file name, not a domain"
    return True, ""


def filter_url(v: str):
    try:
        host = urlparse(v).hostname or ""
    except Exception:
        return False, "unparseable URL"
    if not host:
        return False, "no host"
    try:
        ipaddress.ip_address(host)
        return filter_ip(host)
    except ValueError:
        return filter_domain(host)


# ----------------------------------------------------------------------------- collection
def _tier(sources) -> str:
    best, score = "static", -1
    for s in sources or []:
        for needle, tier in _SRC_TIER:
            if needle in s:
                if TIER_SCORE[tier] > score:
                    best, score = tier, TIER_SCORE[tier]
                break
    return best


def _hash_file(path: Path) -> dict:
    data = path.read_bytes()
    h = {"size": len(data), "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
         "sha256": hashlib.sha256(data).hexdigest()}
    if data[:2] == b"MZ":
        try:
            import pefile
            ih = pefile.PE(data=data, fast_load=False).get_imphash()
            if ih:
                h["imphash"] = ih
        except Exception:
            pass
    return h


def collect(case: dict, case_dir) -> dict:
    """Build the indicator set from everything the analysis recovered."""
    from .detailed_report import _collect_iocs
    st = case.get("stages", {})
    case_dir = Path(case_dir)
    ind, excluded = [], []

    def add(typ, value, usage, sources, context="", tier=None):
        tier = tier or _tier(sources)
        ind.append({"type": typ, "value": value, "usage": usage, "tier": tier,
                    "confidence": TIER_SCORE[tier], "sources": sorted(sources), "context": context})

    def drop(typ, value, reason):
        excluded.append({"type": typ, "value": value, "reason": reason})

    # --- file hashes: the sample, and every dump that is a real, distinct payload
    tri = (st.get("triage") or {}).get("hashes") or {}
    sample_hash = dict(tri)
    sp = Path(case.get("sample") or "")
    if case.get("sample") and sp.is_file():
        sample_hash = _hash_file(sp)
    hashes = [{"name": case.get("name"), "role": "sample (as submitted)", **sample_hash}]
    for d in (st.get("dumps_manifest") or {}).get("dumps", []):
        p = case_dir / d.get("path", "")
        role = d.get("role", "memory dump")
        if d.get("same_as_packed"):
            continue
        if p.exists():
            try:
                hashes.append({"name": d["name"], "role": role, **_hash_file(p)})
                continue
            except Exception:
                pass
        hashes.append({"name": d["name"], "role": role, "size": d.get("size"), "md5": d.get("md5"),
                       "sha256": d.get("sha256")})
    for h in hashes:
        payload = bool(h.get("sha256")) and ("PAYLOAD" in h["role"] or "RECONSTRUCTED" in h["role"] or
                                              "OEP" in h["role"] or h["role"].startswith("sample"))
        for algo in ("sha256", "sha1", "md5", "imphash"):
            if h.get(algo):
                add("file:" + algo, h[algo], "block" if payload else "context",
                    ["sample" if h["role"].startswith("sample") else "unpacked dump: " + h["name"]],
                    h["role"], tier="observed" if payload else "unpacked")

    # --- network (filtered)
    n = _collect_iocs(st)
    for u, srcs in n["urls"].items():
        ok, why = filter_url(u)
        (add("url", u, "block", srcs) if ok else drop("url", u, why))
    for dm, srcs in n["domains"].items():
        ok, why = filter_domain(dm)
        (add("domain", dm, "block", srcs) if ok else drop("domain", dm, why))
    for ip, srcs in n["ips"].items():
        ok, why = filter_ip(ip)
        (add("ipv4", ip, "block", srcs) if ok else drop("ipv4", ip, why))

    # --- host artefacts from every deep-static stage
    stages = {"packed": st.get("deep_static_packed"), "unpacked": st.get("deep_static_unpacked")}
    for s in (st.get("deep_static_decrypted") or {}).get("sources", []):
        stages["decrypted:" + s.get("source", "?")] = s
    for label, ds in stages.items():
        if not ds:
            continue
        src = [f"deep static ({label.split(':')[0]})"]
        for r in ds.get("registry", []):
            add("registry-key", r, "hunt", src)
        for m in ds.get("mutex_hints", []):
            add("mutex", m, "hunt", src)
        for p in ds.get("file_paths", []):
            if USER_PATH.search(p):
                add("file-path", p, "hunt", src)
        for c in ds.get("commands", []):
            if HOST_CMD.search(c):
                add("command-line", c, "hunt", src)
        for ua in ds.get("user_agents", []):
            add("user-agent", ua, "hunt", src)
        for w in ds.get("wallets", []):
            add("crypto-wallet", w, "hunt", src)
        for p in ds.get("pdb_paths", []):
            add("pdb-path", p, "context", src, "build artefact (attribution)")
    # --- behaviour observed on the guest (residue) and ransom artefacts
    res = st.get("residue") or {}
    for r in res.get("new_run_values", []):
        add("registry-run-value", r, "hunt", ["live run (residue)"], tier="observed")
    for p in res.get("new_files", []):
        nm = p.replace("/", "\\").split("\\")[-1]
        add("ransom-note" if NOTE_NAME.search(nm) else "dropped-file", p, "hunt", ["live run (residue)"],
            tier="observed")
    for t in res.get("new_tasks", []):
        add("scheduled-task", t, "hunt", ["live run (residue)"], tier="observed")
    for s in res.get("new_services", []):
        add("service", s, "hunt", ["live run (residue)"], tier="observed")

    # --- behaviour sentinels fired during the live run: strings the sample passed to network / mutex / registry /
    # file / service APIs. These are OBSERVED indicators (tier observed), the strongest kind.
    for ev in (st.get("api_trace") or {}).get("trace", []) or []:
        api = str(ev.get("api", "")).split(".")[-1]
        note = str((ev.get("capture") or {}).get("note", "")).strip()
        if not (ev.get("behavior") or ev.get("cat") == "spawn") or not note.startswith('"'):
            continue
        val = note.strip('"')
        if not val or len(val) > 300:
            continue
        src = [f"live run ({api})"]
        grp = ev.get("behavior")
        if grp == "network":
            if val.lower().startswith(("http://", "https://", "ftp://")):
                ok, why = filter_url(val); (add("url", val, "block", src, tier="observed") if ok else drop("url", val, why))
            else:
                ok, why = filter_domain(val) if not re.fullmatch(r"[\d.]+", val) else filter_ip(val)
                (add("ipv4" if re.fullmatch(r"[\d.]+", val) else "domain", val, "block", src, tier="observed") if ok else drop("domain", val, why))
        elif api == "CreateMutexW":
            add("mutex", val, "hunt", src, tier="observed")
        elif grp == "persist" and api.startswith("Reg"):
            add("registry-key", val, "hunt", src, "name passed to a registry write API", tier="observed")
        elif grp == "persist":
            add("service", val, "hunt", src, tier="observed")
        elif grp == "file" and ("\\" in val or "/" in val) and USER_PATH.search(val):
            add("file-path", val, "hunt", src, tier="observed")
        elif ev.get("cat") == "spawn":
            add("command-line", val, "hunt", src, "command line executed by the sample", tier="observed")

    # --- build / attribution context
    at = st.get("attribution") or {}
    if at.get("compile_timestamp"):
        ts = at["compile_timestamp"]
        add("compile-timestamp", ts.get("iso") or ts.get("utc") or str(ts) if isinstance(ts, dict) else str(ts),
            "context", ["attribution"], "PE header timestamp (can be forged)", tier="static")
    for k, v in (at.get("version_info") or {}).items():
        if k in ("CompanyName", "ProductName", "OriginalFilename", "InternalName") and v:
            add("version-info", f"{k}={v}", "context", ["attribution"], "possible masquerade", tier="static")

    # de-duplicate (same type+value): keep the best tier, merge sources
    best = {}
    for i in ind:
        k = (i["type"], i["value"])
        if k not in best:
            best[k] = i
        else:
            b = best[k]
            b["sources"] = sorted(set(b["sources"]) | set(i["sources"]))
            if i["confidence"] > b["confidence"]:
                b["tier"], b["confidence"] = i["tier"], i["confidence"]
    ind = sorted(best.values(), key=lambda x: (-x["confidence"], x["type"], x["value"]))

    cls = st.get("classification") or {}
    fam = cls.get("primary") if cls.get("primary") not in (None, "unclassified") else None
    cats = [f["family"] for f in cls.get("families", [])][:3]
    return {"schema": "nemesis-analyst/iocs/1", "producer": PRODUCER, "tlp": "AMBER",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sample": {"name": case.get("name"), "sha256": sample_hash.get("sha256"), "size": sample_hash.get("size")},
            "family": fam, "categories": cats, "indicators": ind, "excluded": excluded,
            "availability": availability(ind)}


def availability(ind: list) -> dict:
    """For every indicator class: found, or WHY it is not available — never silently empty."""
    have = lambda *t: sum(1 for i in ind if i["type"] in t)
    net = have("url", "domain", "ipv4")
    hi_net = sum(1 for i in ind if i["type"] in ("url", "domain", "ipv4") and i["confidence"] >= RULE_MIN_TIER)
    out = {
        "file hashes": {"count": have("file:sha256"), "note": "sample + unpacked payloads"},
        "network (C2 / download)": {"count": net, "high_confidence": hi_net, "note":
            "" if hi_net else "none recovered with confidence: the C2 configuration is probably encrypted at rest "
                              "and decrypted only when it beacons — run the detonation phase (FakeNet capture) or "
                              "recover the config key"},
        "host artefacts": {"count": have("registry-key", "registry-run-value", "mutex", "file-path", "command-line",
                                         "dropped-file", "scheduled-task", "service", "ransom-note"),
                           "note": "" if have("registry-key", "registry-run-value", "mutex", "file-path", "command-line",
                                              "dropped-file") else "none observed in the code recovered so far"},
        "build / attribution": {"count": have("pdb-path", "compile-timestamp", "version-info"), "note": ""},
    }
    return out


# ----------------------------------------------------------------------------- writers
def write_json_csv_hashes(pkg: dict, d: Path) -> None:
    (d / "iocs.json").write_text(json.dumps(pkg, indent=2))
    with open(d / "iocs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value", "usage", "confidence", "tier", "sources", "context"])
        for i in pkg["indicators"]:
            w.writerow([i["type"], i["value"], i["usage"], i["confidence"], i["tier"], "; ".join(i["sources"]), i["context"]])
    seen, lines = set(), ["# sha256  sha1  md5  imphash  name  role"]
    by = {}
    for i in pkg["indicators"]:
        if i["type"].startswith("file:"):
            by.setdefault(i["context"] + "|" + (i["sources"][0] if i["sources"] else ""), {})[i["type"][5:]] = i["value"]
    for k, h in by.items():
        role, src = k.split("|", 1)
        line = f"{h.get('sha256','-')}  {h.get('sha1','-')}  {h.get('md5','-')}  {h.get('imphash','-')}  {src}  {role}"
        if line not in seen:
            seen.add(line); lines.append(line)
    (d / "hashes.txt").write_text("\n".join(lines) + "\n")


def _sur_escape(s: str) -> str:
    out = []
    for ch in s:
        out.append({"|": "|7C|", ";": "|3B|", "\\": "|5C|", '"': "|22|", ":": "|3A|"}.get(ch, ch))
    return "".join(out)


def _sid(value: str, used: set) -> int:
    sid = 9_000_000 + int(hashlib.sha1(value.encode()).hexdigest()[:6], 16) % 900_000
    while sid in used:
        sid += 1
    used.add(sid)
    return sid


def suricata_rules(pkg: dict) -> tuple[str, int]:
    used, rules = set(), []
    fam = (pkg.get("family") or "unknown").replace('"', "")
    day = time.strftime("%Y_%m_%d")
    for i in pkg["indicators"]:
        if i["confidence"] < RULE_MIN_TIER or i["usage"] != "block":
            continue
        v, meta = i["value"], f'metadata:created_at {day}, confidence {i["confidence"]}, producer nemesis_labs; '
        msg = f'NEMESIS {fam} {i["type"]} ({i["tier"]})'
        if i["type"] == "domain":
            rules.append(f'alert dns $HOME_NET any -> any any (msg:"{msg}"; dns.query; content:"{_sur_escape(v.lower())}"; '
                         f'nocase; classtype:trojan-activity; sid:{_sid(v, used)}; rev:1; {meta})')
        elif i["type"] == "ipv4":
            rules.append(f'alert ip $HOME_NET any -> {v} any (msg:"{msg}"; classtype:trojan-activity; '
                         f'sid:{_sid(v, used)}; rev:1; {meta})')
        elif i["type"] == "url":
            u = urlparse(v)
            host, path = u.hostname or "", (u.path or "/") + (("?" + u.query) if u.query else "")
            if host:
                rules.append(f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"{msg}"; http.host; content:"{_sur_escape(host)}"; '
                             f'nocase; http.uri; content:"{_sur_escape(path)}"; classtype:trojan-activity; '
                             f'sid:{_sid(v, used)}; rev:1; {meta})')
    return "\n".join(rules) + ("\n" if rules else ""), len(rules)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (s or "x").lower()).strip("_")[:40] or "x"


def sigma_rules(pkg: dict, case: dict) -> list[tuple[str, str]]:
    """(filename, yaml text). Only where the analysis produced the evidence."""
    out, fam = [], pkg.get("family") or "unknown"
    today = time.strftime("%Y/%m/%d")

    def rule(title, desc, logsource, detection, level="medium", fp="Unlikely; review the matching host"):
        rid = str(uuid.uuid5(NS, title + json.dumps(detection, sort_keys=True)))
        body = {"title": title, "id": rid, "status": "experimental", "description": desc,
                "author": PRODUCER, "date": today, "tags": ["attack.impact"] if "ransom" in title.lower() else [],
                "logsource": logsource, "detection": detection, "falsepositives": [fp], "level": level}
        if not body["tags"]:
            del body["tags"]
        import yaml
        return yaml.safe_dump(body, sort_keys=False, allow_unicode=True)

    notes = [i for i in pkg["indicators"] if i["type"] == "ransom-note"]
    if notes:
        names = sorted({i["value"].replace("/", "\\").split("\\")[-1] for i in notes})
        out.append((f"sigma_ransom_note_{_slug(fam)}.yml", rule(
            f"Ransom note file created ({fam})", "Ransom-note file names observed when the sample was run.",
            {"category": "file_event", "product": "windows"},
            {"selection": {"TargetFilename|endswith": [("\\" + n) for n in names]}, "condition": "selection"}, "high")))
    runs = [i for i in pkg["indicators"] if i["type"] == "registry-run-value"]
    if runs:
        vals = sorted({i["value"].split("|")[-1].split("=")[0] for i in runs})
        out.append((f"sigma_run_key_persistence_{_slug(fam)}.yml", rule(
            f"Run-key persistence ({fam})", "Run/RunOnce value created when the sample was run.",
            {"category": "registry_set", "product": "windows"},
            {"selection": {"TargetObject|contains": ["\\CurrentVersion\\Run"], "TargetObject|endswith": [("\\" + v) for v in vals]},
             "condition": "selection"}, "high")))
    cmds = sorted({i["value"] for i in pkg["indicators"] if i["type"] == "command-line"})
    if cmds:
        frag = sorted({m.group(0).lower() for c in cmds for m in [HOST_CMD.search(c)] if m})
        out.append((f"sigma_suspicious_commands_{_slug(fam)}.yml", rule(
            f"Suspicious command line found in sample ({fam})", "Command-line fragments recovered from the sample's code.",
            {"category": "process_creation", "product": "windows"},
            {"selection": {"CommandLine|contains": frag[:8]}, "condition": "selection"},
            "medium", "Administrators legitimately use some of these tools")))
    drops = [i for i in pkg["indicators"] if i["type"] == "dropped-file" and USER_PATH.search(i["value"])]
    if drops:
        out.append((f"sigma_dropped_executable_{_slug(fam)}.yml", rule(
            f"File dropped in a user-writable path ({fam})", "Files created in user-writable locations when the sample was run.",
            {"category": "file_event", "product": "windows"},
            {"selection": {"TargetFilename|endswith": sorted({i["value"].replace("/", "\\").split("\\")[-1] for i in drops})[:10]},
             "condition": "selection"}, "medium")))
    return out


# --- YARA -----------------------------------------------------------------------------------
_API_LIKE = re.compile(r"^(Get|Set|Create|Open|Close|Read|Write|Nt|Zw|Rtl|Virtual|Reg|Crypt|Internet|Http|Load|Free|Query|"
                       r"Find|Delete|Copy|Move|Wait|Exit|Terminate|Heap|Local|Global|Lstr|Wsa|Sock|Process|Thread|Cert|Bcrypt|"
                       r"Sh|Co|Ole|Msg|Dispatch|Is|Init|Enter|Leave|Tls|Fls|Interlocked|Unhandled|Flush|Map|Unmap|Duplicate)"
                       r"[A-Za-z0-9_]{3,40}(A|W|Ex|ExA|ExW)?$")
_BOILER = re.compile(r"(?i)(this program cannot|runtime error|microsoft visual c|msvcr|msvcp|vcruntime|kernel32|user32|advapi32|"
                     r"ntdll|ws2_32|wininet|\.text|\.data|\.rdata|\.rsrc|\.reloc|abcdefghijklmnop|r6\d\d\d|_cexit|"
                     r"mscoree|clrcreateinstance|corexemain|<assembly|xmlns|</|http://schemas)")


def _strings(data: bytes, minlen=8, cap=60000):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group().decode("latin-1"));
        if len(out) >= cap: break
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.append(m.group().decode("utf-16-le", "ignore"))
        if len(out) >= 2 * cap: break
    return out


def _score(s: str) -> float:
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9 ]"))
    return len(set(s)) * 1.0 + min(len(s), 60) * 0.5 + classes * 3 + (6 if ("\\" in s or "/" in s or "%" in s) else 0)


def pick_strings(data: bytes, want=12):
    seen, cands = set(), []
    for s in _strings(data):
        s = s.strip()
        if not (8 <= len(s) <= 120) or s in seen:
            continue
        seen.add(s)
        if _API_LIKE.match(s) or _BOILER.search(s) or len(set(s)) < 5 or re.fullmatch(r"[0-9a-fA-F]+", s):
            continue
        if re.fullmatch(r"[A-Za-z ]+", s) and " " in s and len(s.split()) > 3:      # prose
            continue
        cands.append((_score(s), s))
    cands.sort(reverse=True)
    return [s for _, s in cands[:want]]


def _yara_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def yara_rule(name: str, data: bytes, fam: str, sha256: str, tier: str):
    """(rule_text|None, note). None = withheld because the rule would be noisy."""
    picks = pick_strings(data)
    if len(picks) < 4:
        return None, f"withheld: only {len(picks)} distinctive strings in this stage (need >= 4) — a rule would be noisy"
    k = max(3, int(len(picks) * 0.5))
    is_pe = data[:2] == b"MZ"
    lines = [f"rule {name}", "{", "    meta:",
             f'        author = "{PRODUCER}"', f'        family = "{fam or "unknown"}"',
             f'        sha256 = "{sha256}"', f'        stage = "{tier}"',
             f'        date = "{time.strftime("%Y-%m-%d")}"',
             '        note = "strings chosen automatically; validate against goodware before deployment"',
             "    strings:"]
    for n, s in enumerate(picks):
        lines.append(f"        $s{n} = {_yara_str(s)} ascii wide")
    cond = f"{k} of ($s*)"
    if is_pe:
        cond = f"uint16(0) == 0x5A4D and filesize < {max(len(data) * 4, 100000)} and {cond}"
    lines += ["    condition:", f"        {cond}", "}"]
    return "\n".join(lines) + "\n", f"{len(picks)} strings, needs {k}"


def write_yara(pkg: dict, case: dict, case_dir: Path, goodware_dir=None) -> list[dict]:
    d = case_dir / "intel" / "yara"
    d.mkdir(parents=True, exist_ok=True)
    fam = pkg.get("family") or "unknown"
    st = case.get("stages", {})
    files = []
    sp = Path(case.get("sample") or "")
    if sp.exists():
        files.append(("packed", sp))
    # unpacked stage: the reconstructed PE if there is one, plus every distinct payload-role dump
    # (the W->X region IS the decrypted payload even when PE reconstruction did not run)
    seen_sha, cand = set(), []
    best = ((st.get("pe_reconstruction") or {}).get("best") or {}).get("out")
    for b in ([best] if best else []):
        for pth in (case_dir / b, Path(b)):
            if pth.exists():
                cand.append(pth); break
    for dmp in (st.get("dumps_manifest") or {}).get("dumps", []):
        role = dmp.get("role", "")
        if dmp.get("same_as_packed") or not any(k in role for k in ("PAYLOAD", "RECONSTRUCTED", "OEP")):
            continue
        pth = case_dir / dmp.get("path", "")
        if pth.exists():
            cand.append(pth)
    for pth in sorted(cand, key=lambda x: -x.stat().st_size):
        sha = hashlib.sha256(pth.read_bytes()).hexdigest()
        if sha in seen_sha or len(seen_sha) >= 3:
            continue
        seen_sha.add(sha)
        files.append(("unpacked", pth))
    for p in sorted((case_dir / "dumps").glob("*_decrypted_*.bin")):
        files.append(("decrypted", p))
    results = []
    try:
        import yara
    except Exception:
        yara = None
    for tier, p in files:
        data = p.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        name = f"nemesis_{_slug(fam)}_{tier}_{sha[:8]}"
        text, note = yara_rule(name, data, fam, sha, tier)
        rec = {"stage": tier, "file": p.name, "rule": name, "note": note, "written": False}
        if text and yara:
            try:
                rules = yara.compile(source=text)
                rec["self_match"] = bool(rules.match(data=data))
                if goodware_dir and Path(goodware_dir).exists():
                    fps = [g.name for g in sorted(Path(goodware_dir).iterdir()) if g.is_file() and rules.match(data=g.read_bytes())]
                    n_good = sum(1 for g in Path(goodware_dir).iterdir() if g.is_file())
                    rec["goodware_false_positives"] = f"{len(fps)}/{n_good}"
                    text = text.replace('        note = "strings chosen automatically; validate against goodware before deployment"',
                                        f'        goodware_fp = "{len(fps)}/{n_good} files"')
                    if fps or not rec["self_match"]:
                        text = None; rec["note"] = f"withheld: false positives on goodware {fps[:3]}" if fps else "withheld: does not match its own sample"
                elif not rec["self_match"]:
                    text = None; rec["note"] = "withheld: does not match its own sample"
            except Exception as exc:
                text = None; rec["note"] = f"withheld: YARA rejected the rule ({exc})"
        if text:
            (d / f"{name}.yar").write_text(text)
            rec["written"] = True
        results.append(rec)
    return results


# --- STIX ----------------------------------------------------------------------------------
def stix_bundle(pkg: dict) -> str:
    import stix2
    ident = stix2.Identity(id="identity--" + str(uuid.uuid5(NS, PRODUCER)), name=PRODUCER, identity_class="organization")
    marking = {"AMBER": stix2.TLP_AMBER, "GREEN": stix2.TLP_GREEN, "WHITE": stix2.TLP_WHITE, "CLEAR": stix2.TLP_WHITE}.get(
        pkg.get("tlp", "AMBER"), stix2.TLP_AMBER)
    types = sorted({_MAL[c] for c in pkg.get("categories", []) if c in _MAL}) or ["unknown"]
    fam = pkg.get("family") or "Unidentified malware"
    mal = stix2.Malware(id="malware--" + str(uuid.uuid5(NS, "malware:" + (pkg["sample"].get("sha256") or fam))),
                        name=fam, is_family=False, malware_types=types, created_by_ref=ident.id,
                        object_marking_refs=[marking.id])
    objs = [ident, marking, mal]
    when = pkg["generated"]
    seen = set()
    for i in pkg["indicators"]:
        if i["usage"] != "block" or i["confidence"] < RULE_MIN_TIER:
            continue
        v = i["value"].replace("\\", "\\\\").replace("'", "\\'")
        patt = {"file:sha256": f"[file:hashes.'SHA-256' = '{v}']", "file:sha1": f"[file:hashes.'SHA-1' = '{v}']",
                "file:md5": f"[file:hashes.MD5 = '{v}']", "domain": f"[domain-name:value = '{v}']",
                "ipv4": f"[ipv4-addr:value = '{v}']", "url": f"[url:value = '{v}']"}.get(i["type"])
        if not patt or (i["type"], i["value"]) in seen:
            continue
        seen.add((i["type"], i["value"]))
        iid = "indicator--" + str(uuid.uuid5(NS, i["type"] + i["value"]))
        ind = stix2.Indicator(id=iid, name=f'{i["type"]}: {i["value"]}'[:120], pattern=patt, pattern_type="stix",
                              valid_from=when, indicator_types=["malicious-activity"], confidence=i["confidence"],
                              created_by_ref=ident.id, object_marking_refs=[marking.id],
                              description=f'Tier: {i["tier"]}. Sources: {"; ".join(i["sources"])[:300]}')
        objs.append(ind)
        objs.append(stix2.Relationship(relationship_type="indicates", source_ref=ind.id, target_ref=mal.id,
                                       id="relationship--" + str(uuid.uuid5(NS, iid + mal.id))))
    return stix2.Bundle(objects=objs, allow_custom=False).serialize(pretty=True)


# --- orchestration --------------------------------------------------------------------------
README = """# Detection package

Produced by {producer} from an automated analysis (TLP:{tlp}). Generated {generated}.
Sample SHA-256: `{sha}`    Family: {family}    Categories: {cats}

| File | Use | Trust |
|---|---|---|
| `iocs.json` / `iocs.csv` | every indicator with provenance, tier and intended use | tier tells you how it was obtained |
| `hashes.txt` | sample + unpacked payloads (MD5/SHA-1/SHA-256/imphash) | high for payload hashes |
| `yara/` | one rule per stage | auto-generated; **test against your goodware set** |
| `suricata.rules` | DNS/IP/HTTP rules | only from indicators observed or recovered (tier >= 70) |
| `sigma/` | host-behaviour rules | only where the run produced the evidence |
| `stix.json` | STIX 2.1 bundle | blockable indicators with tier >= 70 only |

## What is NOT available, and why
{avail}

## Limits
* Tiers: observed (on the wire / live run) 90, decrypted 80, unpacked 70, static (strings of the packed file) 40, AI-suggested 20 (never emitted as a rule).
* Filtered-out indicators (known-good domains, private IPs, version numbers) are listed under `excluded` in `iocs.json`.
* A C2 list that is encrypted in the sample cannot be extracted without the key; that is stated above rather than guessed.
"""


def write_package(case: dict, case_dir, goodware_dir=None) -> dict:
    """Write the whole detection package. Never raises: returns a summary (with errors listed)."""
    case_dir = Path(case_dir)
    d = case_dir / "intel"
    d.mkdir(parents=True, exist_ok=True)
    errors, summary = [], {"dir": str(d)}
    try:
        pkg = collect(case, case_dir)
    except Exception as exc:
        return {"dir": str(d), "errors": [f"collect failed: {exc}"]}
    for name, fn in (("json/csv/hashes", lambda: write_json_csv_hashes(pkg, d)),):
        try:
            fn()
        except Exception as exc:
            errors.append(f"{name}: {exc}")
    try:
        text, n = suricata_rules(pkg)
        if n:
            (d / "suricata.rules").write_text(text)
        summary["suricata_rules"] = n
    except Exception as exc:
        errors.append(f"suricata: {exc}")
    try:
        sg = sigma_rules(pkg, case)
        (d / "sigma").mkdir(exist_ok=True)
        for fn, txt in sg:
            (d / "sigma" / fn).write_text(txt)
        summary["sigma_rules"] = len(sg)
    except Exception as exc:
        errors.append(f"sigma: {exc}")
    try:
        summary["yara"] = write_yara(pkg, case, case_dir, goodware_dir)
    except Exception as exc:
        errors.append(f"yara: {exc}")
    try:
        if any(i["usage"] == "block" and i["confidence"] >= RULE_MIN_TIER for i in pkg["indicators"]):
            (d / "stix.json").write_text(stix_bundle(pkg))
            summary["stix"] = True
        else:
            summary["stix"] = False
    except Exception as exc:
        errors.append(f"stix: {exc}")
    av = "\n".join(f"* **{k}**: {v['count']} found" + (f" — {v['note']}" if v.get("note") else "")
                   for k, v in pkg["availability"].items())
    (d / "README.md").write_text(README.format(
        producer=PRODUCER, tlp=pkg["tlp"], generated=pkg["generated"], sha=pkg["sample"].get("sha256"),
        family=pkg.get("family") or "not identified", cats=", ".join(pkg.get("categories") or []) or "not categorised", avail=av))
    summary.update({"indicators": len(pkg["indicators"]), "excluded": len(pkg["excluded"]),
                    "availability": pkg["availability"], "errors": errors,
                    "high_confidence": sum(1 for i in pkg["indicators"] if i["confidence"] >= RULE_MIN_TIER)})
    return summary
