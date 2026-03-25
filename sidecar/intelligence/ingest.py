from __future__ import annotations

import re


def build_multimodal_feature_pack(challenge: dict, files_blob: str, extra: dict) -> dict:
    text = str(files_blob or "")
    attachments = challenge.get("attachments") if isinstance(challenge.get("attachments"), list) else []
    headers = re.findall(r"\[\[attachment:([^\]]+)\]\]", text)
    descriptors = attachments if attachments else []

    modalities = set()
    feature_bag = {
        "binary": [],
        "network": [],
        "image": [],
        "doc": [],
        "archive": [],
        "source": [],
    }

    def _classify_name(name: str, ftype: str = ""):
        raw = f"{name} {ftype}".lower()
        if re.search(r"\.(elf|exe|dll|so|bin)$", raw):
            modalities.add("binary")
            feature_bag["binary"].append(name)
        elif re.search(r"\.(pcap|pcapng)$", raw):
            modalities.add("network")
            feature_bag["network"].append(name)
        elif re.search(r"\.(png|jpg|jpeg|gif|bmp|webp|tiff)$", raw):
            modalities.add("image")
            feature_bag["image"].append(name)
        elif re.search(r"\.(pdf|doc|docx|rtf|odt)$", raw):
            modalities.add("doc")
            feature_bag["doc"].append(name)
        elif re.search(r"\.(zip|tar|gz|7z|rar)$", raw):
            modalities.add("archive")
            feature_bag["archive"].append(name)
        elif re.search(r"\.(py|js|ts|java|go|rs|c|cpp|h|php|html|css|json|yaml|yml|xml)$", raw):
            modalities.add("source")
            feature_bag["source"].append(name)

    for h in headers:
        _classify_name(h)
    for a in descriptors:
        if isinstance(a, dict):
            _classify_name(str(a.get("name", "")), str(a.get("type", "")))

    lower_text = text.lower()
    if any(x in lower_text for x in ("png", "jpeg", "exif", "steg")):
        modalities.add("image")
    if any(x in lower_text for x in ("pcap", "http/1.1", "dns", "tcp stream")):
        modalities.add("network")
    if any(x in lower_text for x in ("elf", "checksec", "rop", "libc")):
        modalities.add("binary")

    return {
        "modalities": sorted(modalities),
        "feature_bag": {k: v[:10] for k, v in feature_bag.items() if v},
        "attachment_count": len(headers) if headers else len(descriptors),
        "ingest_mode": "native_structured",
        "planner_hint": "Prioritize modality-specific tools before generic brute-force.",
    }


def render_multimodal_for_prompt(pack: dict) -> str:
    if not pack:
        return ""
    lines = ["## Multimodal Ingest", f"Modalities: {', '.join(pack.get('modalities', [])) or 'text-only'}"]
    fb = pack.get("feature_bag", {}) if isinstance(pack.get("feature_bag"), dict) else {}
    for key in ("binary", "network", "image", "doc", "archive", "source"):
        vals = fb.get(key, [])
        if vals:
            lines.append(f"- {key}: {', '.join(vals[:6])}")
    lines.append(f"Planner hint: {pack.get('planner_hint','')}")
    return "\n".join(lines)
