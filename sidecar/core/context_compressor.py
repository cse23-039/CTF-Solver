"""Compress accumulated tool results to prevent context overflow on long solves."""
from __future__ import annotations

import re

MAX_TOOL_RESULT_CHARS = 2800
MAX_MESSAGES_BEFORE_COMPRESS = 14
KEEP_RECENT_MESSAGES = 8

_PRIORITY_RE = re.compile(
    r"flag\{|0x[0-9a-fA-F]{4,}|RIP|RSP|RBP|overflow|canary|leak|gadget|"
    r"SECRET|KEY|PASS|TOKEN|CVE-|ret2|shellcode|system\(|execve|win\(|"
    r"ERROR|FATAL|Exception|Traceback|found|success|solved",
    re.IGNORECASE,
)


def compress_tool_result(content: str) -> str:
    """Trim a large tool output to the most signal-dense lines."""
    if not content or len(content) <= MAX_TOOL_RESULT_CHARS:
        return content

    lines = content.splitlines()
    priority = [line for line in lines if _PRIORITY_RE.search(line)]
    rest = [line for line in lines if not _PRIORITY_RE.search(line)]

    head = rest[:25]
    tail = rest[-25:]
    middle_marker = ["...[middle trimmed for context efficiency]..."] if len(rest) > 50 else []
    condensed_lines = priority + head + middle_marker + tail

    result = "\n".join(condensed_lines)
    if len(result) > MAX_TOOL_RESULT_CHARS:
        return result[:MAX_TOOL_RESULT_CHARS] + "\n...[truncated — full result in workspace]..."
    return result


def maybe_compress_messages(messages: list) -> list:
    """
    Compress old tool results when conversation history grows large.

    Strategy:
    - Keep first 2 messages (initial challenge + first response) verbatim
    - Keep last KEEP_RECENT_MESSAGES verbatim (most recent context is critical)
    - Compress tool_result blocks in the middle (shrink output, keep signal lines)
    """
    if len(messages) < MAX_MESSAGES_BEFORE_COMPRESS:
        return messages

    head = messages[:2]
    tail = messages[-KEEP_RECENT_MESSAGES:]
    middle = messages[2:-KEEP_RECENT_MESSAGES]

    compressed_middle = []
    for msg in middle:
        if msg.get("role") == "user" and isinstance(msg.get("content"), list):
            new_content = []
            for block in msg["content"]:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    inner = block.get("content", [])
                    new_inner = []
                    for item in inner:
                        if isinstance(item, dict) and item.get("type") == "text":
                            compressed_text = compress_tool_result(item.get("text", ""))
                            item = {**item, "text": compressed_text}
                        new_inner.append(item)
                    new_content.append({**block, "content": new_inner})
                else:
                    new_content.append(block)
            compressed_middle.append({**msg, "content": new_content})
        else:
            compressed_middle.append(msg)

    return head + compressed_middle + tail
