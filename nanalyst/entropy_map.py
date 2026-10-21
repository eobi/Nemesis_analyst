"""Entropy map: where, exactly, the encrypted/compressed bytes are.

A single whole-file entropy number says "packed"; it doesn't say WHERE the payload is. This
walks the file in fixed blocks, merges runs of high-entropy blocks into regions with file
offset + RVA + owning section, and also inspects the overlay (bytes after the last section)
and resources (a classic payload carrier). The AI static analysis and the dynamic plan use
these concrete locations.

Deterministic, host-side, no network.
"""
from __future__ import annotations

import math
from collections import Counter

BLOCK = 4096
HIGH = 7.2      # >= this per block looks encrypted/compressed
MIN_BLOCKS = 2  # a region must span at least this many consecutive high blocks (or be a resource/overlay)


def shannon(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return round(-sum((c / n) * math.log2(c / n) for c in Counter(b).values()), 3)


def merge_blocks(ents: list, base_off: int, block: int = BLOCK, hi: float = HIGH,
                 min_blocks: int = MIN_BLOCKS) -> list:
    """Merge consecutive high-entropy blocks. `ents` = per-block entropies starting at file
    offset `base_off`. Returns [{file_off, size, entropy(avg), blocks}]."""
    out, run = [], []
    for i, e in enumerate(ents + [0.0]):          # sentinel flushes the last run
        if e >= hi:
            run.append((i, e))
            continue
        if len(run) >= min_blocks:
            first, last = run[0][0], run[-1][0]
            out.append({"file_off": base_off + first * block,
                        "size": (last - first + 1) * block,
                        "entropy": round(sum(x for _, x in run) / len(run), 3),
                        "blocks": len(run)})
        run = []
    return out


def map_regions(path: str, block: int = BLOCK) -> dict:
    """Entropy map of a PE (falls back to flat blocks for a non-PE). Never raises."""
    data = open(path, "rb").read()
    res = {"file_size": len(data), "file_entropy": shannon(data), "block": block,
           "sections": [], "regions": [], "overlay": None, "resources": []}
    try:
        import pefile
        pe = pefile.PE(data=data)
    except Exception:
        ents = [shannon(data[i:i + block]) for i in range(0, len(data), block)]
        res["regions"] = [dict(r, section=None, rva=None, kind="high-entropy")
                          for r in merge_blocks(ents, 0, block)]
        return res

    res["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
    res["size_of_image"] = int(pe.OPTIONAL_HEADER.SizeOfImage)
    res["entry_rva"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    end_of_sections = 0
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        off, size, rva = int(s.PointerToRawData), int(s.SizeOfRawData), int(s.VirtualAddress)
        end_of_sections = max(end_of_sections, off + size)
        chunk = data[off:off + size]
        ents = [shannon(chunk[i:i + block]) for i in range(0, len(chunk), block)]
        res["sections"].append({
            "name": name, "file_off": off, "raw_size": size, "rva": hex(rva),
            "vsize": int(s.Misc_VirtualSize), "entropy": shannon(chunk),
            "exec": bool(s.Characteristics & 0x20000000), "write": bool(s.Characteristics & 0x80000000),
            # virtual >> raw: the section only fills in at runtime (a decompression/decryption target)
            "runtime_expanded": int(s.Misc_VirtualSize) > max(size, 1) * 4 and int(s.Misc_VirtualSize) > 0x10000,
        })
        for r in merge_blocks(ents, off, block):
            r.update(section=name, rva=hex(rva + (r["file_off"] - off)), kind="high-entropy")
            res["regions"].append(r)

    if len(data) > end_of_sections + 512:         # overlay: appended data, often an encrypted payload
        ov = data[end_of_sections:]
        res["overlay"] = {"file_off": end_of_sections, "size": len(ov), "entropy": shannon(ov)}
        if res["overlay"]["entropy"] >= HIGH:
            res["regions"].append({"file_off": end_of_sections, "size": len(ov), "entropy": res["overlay"]["entropy"],
                                   "blocks": max(1, len(ov) // block), "section": "(overlay)", "rva": None,
                                   "kind": "high-entropy overlay"})
    try:                                           # resources: type/name/lang/size/entropy
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for rt in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None).entries:
            for rn in getattr(rt, "directory", rt).entries:
                for rl in rn.directory.entries:
                    d = rl.data.struct
                    raw = pe.get_data(d.OffsetToData, d.Size)
                    e = shannon(raw)
                    if d.Size >= 1024:
                        item = {"type": str(rt.name or rt.id), "name": str(rn.name or rn.id),
                                "size": int(d.Size), "entropy": e,
                                "file_off": int(pe.get_offset_from_rva(d.OffsetToData)),
                                "rva": hex(int(d.OffsetToData))}
                        res["resources"].append(item)
                        if e >= HIGH:
                            res["regions"].append({"file_off": item["file_off"], "size": item["size"], "entropy": e,
                                                   "blocks": max(1, item["size"] // block), "section": ".rsrc",
                                                   "rva": item["rva"], "kind": f"high-entropy resource {item['type']}/{item['name']}"})
    except Exception:
        pass
    # TLS callbacks run BEFORE the debugger's entry stop — code the sample controls, uncontrolled by us
    res["tls_callbacks"] = []
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        cb = int(tls.struct.AddressOfCallBacks) if tls else 0
        base = pe.OPTIONAL_HEADER.ImageBase
        ptr = 8 if pe.FILE_HEADER.Machine == 0x8664 else 4
        while cb and len(res["tls_callbacks"]) < 16:
            raw = pe.get_data(cb - base, ptr)
            va = int.from_bytes(raw, "little")
            if not va:
                break
            res["tls_callbacks"].append(hex(va - base))             # RVA of each callback
            cb += ptr
    except Exception:
        pass
    res["resources"] = sorted(res["resources"], key=lambda x: -x["size"])[:12]
    res["regions"] = sorted(res["regions"], key=lambda r: -r["size"])[:16]
    return res
