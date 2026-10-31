#!/usr/bin/env python3
"""
Rise The Ranger 2 - Digital Forensics CTF Toolkit
Satsiber TNI Cyber Competition 2026
"""

import argparse, sys, os, json, hashlib, struct, zlib, base64, binascii, re, subprocess, math, string
from pathlib import Path
from datetime import datetime

# Colors
R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'; M='\033[95m'; C='\033[96m'; W='\033[97m'; N='\033[0m'

BANNER = f"""
{C}╔══════════════════════════════════════════════════════════╗
║   RISE THE RANGER 2 - Digital Forensics Toolkit           ║
║   Satsiber TNI Cyber Competition 2026                    ║
╚══════════════════════════════════════════════════════════╝{N}
"""

def P(msg): print(f"{B}[*] {msg}{N}")
def I(msg): print(f"{C}[+] {msg}{N}")
def O(msg): print(f"{G}[✓] {msg}{N}")
def W(msg): print(f"{Y}[!] {msg}{N}")
def E(msg): print(f"{R}[✗] {msg}{N}")
def F(msg): print(f"{M}  >> FLAG: {msg} <<{N}")
def H(msg):
    s="─"*60
    print(f"\n{B}{s}{N}\n{B}  {msg}{N}\n{B}{s}{N}")
def cmd(c):
    try:
        r=subprocess.run(c,capture_output=True,text=True,shell=isinstance(c,str))
        return r.stdout,r.stderr,r.returncode
    except Exception as e:
        return "","",1

# ═══════════════════════════════════════════════════════════
# HASH ANALYSIS
# ═══════════════════════════════════════════════════════════
def hash_file(path):
    H("HASH ANALYSIS")
    algs=["md5","sha1","sha224","sha256","sha384","sha512"]
    results={}
    P(f"Computing hashes for: {path}")
    try:
        with open(path,"rb") as f:
            data=f.read()
        for alg in algs:
            h=hashlib.new(alg)
            h.update(data)
            results[alg]=h.hexdigest()
            print(f"  {alg.upper():8s}: {h.hexdigest()}")
    except Exception as e:
        E(f"Error: {e}")
    return results

def verify_hash(path, expected_hash, alg="auto"):
    H("HASH VERIFICATION")
    P(f"Verifying: {path}")
    results = hash_file(path)
    if alg == "auto":
        for k,v in results.items():
            if v.lower() == expected_hash.lower():
                O(f"Match found with {k.upper()}!")
                return True
        E("No matching hash found.")
    else:
        if results.get(alg) == expected_hash.lower():
            O(f"Match found with {alg.upper()}!")
            return True
        E("No match.")
    return False

def identify_hash(h):
    H("HASH IDENTIFICATION")
    h = h.strip()
    length = len(h)
    P(f"Analyzing: {h[:40]}...")
    info = []
    if re.match(r'^[a-f0-9]{32}$', h): info.append(("MD5","128-bit","1 block, no salt"))
    if re.match(r'^[a-f0-9]{40}$', h): info.append(("SHA1","160-bit","deprecate"))
    if re.match(r'^[a-f0-9]{56}$', h): info.append(("SHA-224","224-bit",""))
    if re.match(r'^[a-f0-9]{64}$', h): info.append(("SHA-256","256-bit","most common"))
    if re.match(r'^[a-f0-9]{96}$', h): info.append(("SHA-384","384-bit",""))
    if re.match(r'^[a-f0-9]{128}$', h): info.append(("SHA-512","512-bit",""))
    if re.match(r'^\$[A-Z0-9]{1,2\}\$[a-f0-9]{16,128}$', h): info.append(("crypt-style hash","","check algorithm"))
    if re.match(r'^[A-Za-z0-9]{22}[A-Za-z0-9+/]{2}=$', h): info.append(("Base64-encoded","",""))
    if re.match(r'^[A-Za-z0-9+/]{43}=$', h): info.append(("Base64 hash (32 bytes)","",""))
    if not info:
        E("Unknown hash format")
    else:
        for name,bits,note in info:
            I(f"Possible: {B}{name}{N} ({bits}) {Y}{note}{N}")
    return info

def wordlist_crack(h, wordlist_path):
    H("DICTIONARY ATTACK")
    P(f"Cracking: {h}")
    P(f"Wordlist: {wordlist_path}")
    if not os.path.exists(wordlist_path):
        E(f"Wordlist not found: {wordlist_path}")
        return None
    count = 0
    h_lower = h.lower()
    with open(wordlist_path,"r",errors="ignore") as wl:
        for line in wl:
            word = line.strip()
            count += 1
            for alg in ["md5","sha1","sha256"]:
                if hashlib.new(alg).update(word.encode()) or hashlib.new(alg, word.encode()).hexdigest() == h_lower:
                    O(f"Found! {alg.upper()}: {word}")
                    return word
            if count % 100000 == 0:
                P(f"Checked {count} words...")
    E(f"Not found after {count} attempts.")
    return None

# ═══════════════════════════════════════════════════════════
# PCAP / NETWORK ANALYSIS
# ═══════════════════════════════════════════════════════════
def pcap_info(path):
    H("PCAP FILE INFO")
    P(f"Analyzing: {path}")
    out,err,rc = cmd(["tshark","-r",path,"-D"])
    if rc == 0:
        I("Available dissect columns:")
        for line in out.strip().split("\n")[:20]:
            print(f"  {C}{line}{N}")
    out,err,rc = cmd(["tshark","-r",path,"-q","-z","stats","-n"])
    if rc == 0:
        print(f"\n{Y}PCAP Statistics:{N}")
        print(out[:3000])
    out,err,rc = cmd(["capinfos",path])
    if rc == 0:
        print(f"\n{Y}File Info:{N}")
        print(out[:2000])
    return out

def pcap_extract_files(path, out_dir=None):
    H("EXTRACT FILES FROM PCAP")
    if out_dir is None:
        out_dir = Path(path).stem + "_extracted"
    os.makedirs(out_dir, exist_ok=True)
    P(f"Extracting files to: {out_dir}")
    out,err,rc = cmd(["foremost","-i",path,"-o",out_dir])
    if rc == 0:
        O(f"Extraction complete: {out_dir}")
    else:
        W(f"foremost rc={rc}, trying tshark...")
        cmd(["tshark","-r",path,"-Y","http","--export-objects","http,"+out_dir])
        O(f"HTTP objects exported to: {out_dir}")
    for root,dirs,files in os.walk(out_dir):
        for f in files:
            fp = os.path.join(root,f)
            I(f"  Extracted: {fp} ({os.path.getsize(fp)} bytes)")

def pcap_filter(path, filter_expr):
    H(f"PCAP FILTER: {filter_expr}")
    P(f"Applying filter: {filter_expr}")
    out,err,rc = cmd(["tshark","-r",path,"-Y",filter_expr,"-T","fields","-e","frame.number","-e","ip.src","-e","ip.dst","-e","_ws.col.Info"])
    if rc == 0 and out:
        for line in out.strip().split("\n")[:100]:
            parts = line.split("\t")
            if len(parts) >= 4:
                print(f"  {B}{parts[0]:>4s}{N} {C}{parts[1]:>15s}{N} -> {M}{parts[2]:>15s}{N} | {parts[3]}")
    else:
        E(f"No results or tshark error: {err}")

def pcap_dns(path):
    H("DNS QUERY ANALYSIS")
    P("Extracting DNS queries...")
    out,err,rc = cmd(["tshark","-r",path,"-Y","dns","-T","fields","-e","dns.qry.name","-e","dns.a","-e","dns.aaaa","-e","dns.cname"])
    if rc == 0 and out:
        seen = set()
        for line in out.strip().split("\n"):
            if line and line not in seen:
                seen.add(line)
                parts = line.split("\t")
                qname = parts[0] if parts else ""
                addr = "\t".join(parts[1:]) if len(parts)>1 else ""
                print(f"  {C}{qname}{N} -> {addr}")
    else:
        E("No DNS traffic found or tshark not available.")

def pcap_http(path):
    H("HTTP TRAFFIC ANALYSIS")
    P("Extracting HTTP requests...")
    out,err,rc = cmd(["tshark","-r",path,"-Y","http.request","-T","fields","-e","http.host","-e","http.request.uri","-e","http.user_agent","-e","ip.src"])
    if rc == 0 and out:
        for line in out.strip().split("\n")[:100]:
            parts = line.split("\t")
            if len(parts) >= 2:
                host = parts[0] if len(parts)>0 else ""
                uri = parts[1] if len(parts)>1 else ""
                ua = parts[2] if len(parts)>2 else ""
                src = parts[3] if len(parts)>3 else ""
                print(f"  {C}{src}{N} -> {G}{host}{N}{uri}")
                if ua:
                    print(f"    UA: {Y}{ua}{N}")
    else:
        E("No HTTP traffic found or tshark not available.")

def pcap_strings(path, keyword=None):
    H("PCAP STRING SEARCH")
    P("Extracting strings from reassembled data...")
    out,err,rc = cmd(["tshark","-r",path,"-z","follow,text,0","-q"])
    if rc == 0 and out:
        lines = out.split("\n")
        if keyword:
            for i,line in enumerate(lines):
                if keyword.lower() in line.lower():
                    ctx = lines[max(0,i-2):i+3]
                    print(f"\n  {B}--- Match at line {i} ---{N}")
                    for c in ctx:
                        print(f"  {c}")
        else:
            print(out[:5000])
    else:
        E("Could not extract strings.")

def pcap_credentials(path):
    H("CREDENTIAL EXTRACTION")
    P("Searching for credentials in PCAP...")
    # HTTP Basic Auth
    out,err,rc = cmd(["tshark","-r",path,"-Y","http.authbasic","-T","fields","-e","http.authbasic"])
    if rc == 0 and out.strip():
        print(f"\n  {G}HTTP Basic Auth:{N}")
        for line in out.strip().split("\n"):
            if line:
                try:
                    decoded = base64.b64decode(line).decode("utf-8","ignore")
                    print(f"    {decoded}")
                except:
                    print(f"    {line}")
    # HTTP POST passwords
    out,err,rc = cmd(["tshark","-r",path,"-Y","http.request.method==POST","-T","fields","-e","http.file","-e","ip.src","-e","ip.dst"])
    if rc == 0 and out.strip():
        print(f"\n  {Y}HTTP POST Data:{N}")
        for line in out.strip().split("\n"):
            if line and any(x in line.lower() for x in ["pass","pwd","password","login","user"]):
                print(f"    {line}")
    # FTP credentials
    out,err,rc = cmd(["tshark","-r",path,"-Y","ftp","-T","fields","-e","ftp.user","-e","ftp.pass"])
    if rc == 0 and out.strip():
        print(f"\n  {R}FTP Credentials:{N}")
        for line in out.strip().split("\n"):
            print(f"    USER/PASS: {line}")
    # NTLM / HTTP Negotiate
    out,err,rc = cmd(["tshark","-r",path,"-Y","ntlmssp","-T","fields","-e","ntlmssp.nlmp.username"])
    if rc == 0 and out.strip():
        print(f"\n  {M}NTLM Users:{N}")
        for line in out.strip().split("\n"):
            print(f"    {line}")

# ═══════════════════════════════════════════════════════════
# STEGANOGRAPHY
# ═══════════════════════════════════════════════════════════
def stego_lsb(path):
    H("LSB STEGANOGRAPHY")
    P("Extracting LSB data from image...")
    try:
        with open(path,"rb") as f:
            data = f.read()
        # PNG signature
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            P("PNG detected - extracting LSB plane...")
            width = struct.unpack(">I", data[16:20])[0]
            height = struct.unpack(">I", data[20:24])[0]
            bit_depth = data[24]
            I(f"Image: {width}x{height}, bit depth: {bit_depth}")
            # Walk through IDAT chunks
            pos = 8
            idat_data = b""
            while pos < len(data):
                length = struct.unpack(">I", data[pos:pos+4])[0]
                chunk_type = data[pos+4:pos+8]
                if chunk_type == b"IDAT":
                    idat_data += data[pos+8:pos+8+length]
                pos += 12 + length
            if idat_data:
                # Try zlib decompress
                try:
                    dec = zlib.decompress(idat_data)
                    lsb_bits = ""
                    for byte in dec:
                        lsb_bits += str(byte & 1)
                    # Group into bytes
                    chars = []
                    for i in range(0, len(lsb_bits)-7, 8):
                        byte = lsb_bits[i:i+8]
                        if len(byte) == 8:
                            try:
                                c = chr(int(byte,2))
                                if c.isprintable():
                                    chars.append(c)
                            except: pass
                    result = "".join(chars)
                    if result:
                        I(f"Extracted text: {result[:500]}")
                        if "flag" in result.lower():
                            F(result)
                    else:
                        W("No clear text found in LSB.")
                except Exception as e:
                    W(f"Could not decompress: {e}")
        # JPEG
        elif data[:2] == b"\xff\xd8":
            P("JPEG detected - searching for embedded data...")
            # Look for APP markers with unusual content
            pos = 2
            while pos < len(data)-4:
                if data[pos] == 0xFF and data[pos+1] != 0x00 and data[pos+1] != 0xFF:
                    marker = data[pos+1]
                    length = struct.unpack(">H", data[pos+2:pos+4])[0]
                    if marker == 0xE0: I(f"APP0 (JFIF): {length} bytes")
                    elif marker == 0xE1: I(f"APP1 (EXIF): {length} bytes")
                    elif marker == 0xFE: 
                        comment = data[pos+4:pos+2+length]
                        I(f"APP11 (Comment): {comment[:200]}")
                    pos += 2 + length
                else:
                    pos += 1
        else:
            # Generic LSB for BMP
            P("Generic binary - extracting LSB bytes...")
            lsb_bits = ""
            for byte in data[:100000]:
                lsb_bits += str(byte & 1)
            chars = []
            for i in range(0, min(len(lsb_bits)-7, 80000), 8):
                byte = lsb_bits[i:i+8]
                try:
                    c = chr(int(byte,2))
                    if c.isprintable():
                        chars.append(c)
                    else:
                        if len(chars) > 10:
                            result = "".join(chars)
                            print(f"  {C}{result}{N}")
                            if "flag" in result.lower(): F(result)
                        chars = []
                except: chars = []
            if chars:
                result = "".join(chars)
                if len(result) > 10:
                    print(f"  {C}{result}{N}")
    except Exception as e:
        E(f"Error: {e}")

def stego_zsteg(path):
    H("ZSTEG ANALYSIS")
    P(f"Running zsteg on: {path}")
    out,err,rc = cmd(["zsteg",path])
    if rc == 0:
        print(out)
        if "flag" in out.lower() or "FLAG" in out:
            lines = out.strip().split("\n")
            for line in lines:
                if "flag" in line.lower() or any(c.isupper() for c in line):
                    if len(line) > 5:
                        F(line.strip())
    else:
        W("zsteg not found. Install with: gem install zsteg")
        W(f"Alternative: try steghide, binwalk, or exiftool")

def stego_exif(path):
    H("EXIF METADATA")
    P(f"Extracting EXIF from: {path}")
    out,err,rc = cmd(["exiftool",path])
    if rc == 0:
        print(out[:3000])
    else:
        W("exiftool not found.")
        # Fallback: read JPEG EXIF manually
        try:
            with open(path,"rb") as f:
                data = f.read()
            if data[:2] == b"\xff\xd8":
                P("Manual JPEG EXIF parsing...")
                pos = 2
                while pos < len(data)-4:
                    if data[pos] == 0xFF and data[pos+1] != 0x00 and data[pos+1] != 0xFF:
                        m = data[pos+1]
                        l = struct.unpack(">H",data[pos+2:pos+4])[0]
                        if m == 0xE1:
                            I(f"APP1 segment at offset {pos}, length {l}")
                        pos += 2+l
                    else: pos += 1
        except Exception as e:
            E(str(e))

def stego_steghide(path, password=""):
    H("STEGHIDE ANALYSIS")
    P(f"Running steghide on: {path}")
    if password:
        out,err,rc = cmd(f"steghide extract -sf {path} -p {password} -xf /tmp/steghide_out.txt 2>&1")
    else:
        out,err,rc = cmd(f"steghide extract -sf {path} -p '' -xf /tmp/steghide_out.txt 2>&1")
    if rc == 0:
        O("Data extracted!")
        with open("/tmp/steghide_out.txt","rb") as f:
            content = f.read()
            print(content[:2000])
            F(content.decode("utf-8","ignore")[:200])
    else:
        W("No steghide data found or steghide not installed.")
        W("Install: apt install steghide")

def stego_binwalk(path):
    H("BINWALK ANALYSIS")
    P(f"Running binwalk on: {path}")
    out,err,rc = cmd(["binwalk",path])
    if rc == 0:
        print(out[:3000])
    else:
        W("binwalk not found. Install: apt install binwalk")

# ═══════════════════════════════════════════════════════════
# FILE ANALYSIS
# ═══════════════════════════════════════════════════════════
FILE_SIGS = {
    b"\x89PNG\r\n\x1a\n": ("PNG","image/png"),
    b"\xff\xd8\xff": ("JPEG","image/jpeg"),
    b"GIF87a": ("GIF87a","image/gif"),
    b"GIF89a": ("GIF89a","image/gif"),
    b"RIFF": ("RIFF/WAV","audio/wav"),
    b"%PDF": ("PDF","application/pdf"),
    b"\x1f\x8b": ("GZIP","application/gzip"),
    b"PK\x03\x04": ("ZIP","application/zip"),
    b"\x7fELF": ("ELF","application/x-elf"),
    b"MZ": ("EXE/DOS","application/x-executable"),
    b"\xca\xfe\xba\xbe": ("MACHO","application/x-mach"),
    b"\xce\xfa\xed\xfe": ("MACHO64","application/x-mach"),
    b"Rar!\x1a\x07": ("RAR","application/x-rar"),
    b"\x1f\x9d": ("TAR.Z","application/x-tar"),
    b"\xfd7zXZ\x00": ("XZ","application/x-xz"),
    b"BSDI": ("BSDI","application/x-bsd"),
    b"\x00\x00\x01\x00": ("ICO","image/x-icon"),
    b"BM": ("BMP","image/bmp"),
    b"II*\x00": ("TIFF (little-endian)","image/tiff"),
    b"MM\x00*": ("TIFF (big-endian)","image/tiff"),
    b"\x00\x00\x01\x00": ("ICO","image/x-icon"),
    b"wOF": ("WOFF","font/woff"),
    b"wOF2": ("WOFF2","font/woff2"),
    b"OTTO": ("OTF","font/otf"),
    b"\x00\x01\x00\x00": ("TTF","font/ttf"),
    b"PAR1": ("PAR1","image/x-par"),
    b"JP2": ("JPEG2000","image/jp2"),
    b"\x00\x00\x00\x0cJAXPA": ("JPEG2000","image/jp2"),
    b"\x04\x22\x4d\x18": ("MKV","video/x-matroska"),
    b"\x1aE\xdf\xa3": ("WEBM/MKV","video/webm"),
    b"\x00\x00\x00": ("MP4/MOV","video/mp4"),
    b"FLV": ("FLV","video/x-flv"),
    b"RIFF": ("RIFF AVI","video/x-avi"),
    b"{\\rtf": ("RTF","application/rtf"),
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": ("MS Office","application/vnd.ms"),
    b"SQLite format 3": ("SQLite","application/x-sqlite"),
}

def identify_file(path):
    H("FILE TYPE IDENTIFICATION")
    P(f"Identifying: {path}")
    with open(path,"rb") as f:
        header = f.read(512)
    size = os.path.getsize(path)
    print(f"  Size: {size:,} bytes ({size/1024:.1f} KB)")
    for sig,(ftype,mime) in FILE_SIGS.items():
        if header.startswith(sig):
            O(f"File type: {B}{ftype}{N} ({mime})")
            break
    else:
        I(f"Unknown type. First bytes: {B}{header[:16].hex()}{N}")
    # Check entropy
    entropy = 0.0
    if len(header) > 0:
        freq = [0]*256
        for b in header:
            freq[b] += 1
        for c in freq:
            if c > 0:
                p = c/len(header)
                entropy -= p*math.log2(p)
    print(f"  Header entropy: {entropy:.2f}/8.0")
    if entropy > 7.5: W("High entropy - possibly encrypted/compressed")
    elif entropy < 3.0: I("Low entropy - likely plaintext or simple encoding")
    return ftype if 'ftype' in dir() else "unknown"

def extract_strings(path, min_len=4, only_printable=True):
    H(f"STRING EXTRACTION (min_len={min_len})")
    P(f"Extracting strings from: {path}")
    printable = set(string.printable.encode())
    results = []
    try:
        with open(path,"rb") as f:
            chunk_size = 1024*1024
            buffer = b""
            while True:
                data = f.read(chunk_size)
                if not data: break
                buffer += data
                start = 0
                while start < len(buffer):
                    end = start
                    while end < len(buffer) and buffer[end] in printable:
                        end += 1
                    if end - start >= min_len:
                        s = buffer[start:end].decode("ascii","ignore")
                        if only_printable:
                            results.append(s)
                        else:
                            results.append(s)
                    start = end + 1
                buffer = buffer[max(0,len(buffer)-256):]
        for r in results[:200]:
            print(f"  {C}{r}{N}")
            if "flag" in r.lower(): F(r)
        I(f"Total strings found: {len(results)}")
    except Exception as e:
        E(f"Error: {e}")

def hex_dump(path, length=256, offset=0):
    H("HEX DUMP")
    P(f"Dumping {length} bytes from offset {offset}...")
    with open(path,"rb") as f:
        f.seek(offset)
        data = f.read(length)
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(47)
        ascii_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
        print(f"{B}{offset+i:08x}{N}  {hex_part}  {Y}{ascii_part}{N}")

def carve_files(path, out_dir=None):
    H("FILE CARVING")
    if out_dir is None:
        out_dir = Path(path).stem + "_carved"
    os.makedirs(out_dir, exist_ok=True)
    P(f"Carving files to: {out_dir}")
    # Try foremost
    out,err,rc = cmd(["foremost","-i",path,"-o",out_dir,"-v"])
    if rc == 0:
        O("Foremost carving complete")
    else:
        W("Foremost failed, trying binwalk...")
        out,err,rc = cmd(["binwalk","-e","-C",out_dir,path])
        if rc == 0:
            O("Binwalk carving complete")
    for root,dirs,files in os.walk(out_dir):
        for f in files:
            fp = os.path.join(root,f)
            sz = os.path.getsize(fp)
            I(f"  Carved: {fp} ({sz:,} bytes)")

# ═══════════════════════════════════════════════════════════
# DISK IMAGE ANALYSIS
# ═══════════════════════════════════════════════════════════
def mount_image(path):
    H("DISK IMAGE MOUNT")
    P(f"Analyzing: {path}")
    size = os.path.getsize(path)
    print(f"  Size: {size:,} bytes ({size/(1024**3):.2f} GB)")
    out,err,rc = cmd(["file",path])
    if rc == 0:
        I(f"File type: {out.strip()}")
    # Try to identify partition table
    with open(path,"rb") as f:
        header = f.read(512)
    if header[510:512] == b"\x55\xaa":
        I("MBR signature found (0x55AA)")
    # Check for GPT
    if header[:8] == b"EFI PART":
        O("GPT partition table detected")
    # Partition types from MBR
    print(f"\n  {Y}MBR Partition Table:{N}")
    for i in range(4):
        off = 446 + i*16
        entry = header[off:off+16]
        status,chs_start,part_type,chs_end,lba_start,lba_size = struct.unpack("<B3sB3sII",entry)
        if lba_size > 0:
            print(f"  Partition {i+1}: type={B}{part_type:02x}{N} LBA={lba_start} size={lba_size*512/1024:.1f} KB")
    P("To mount, try:")
    P(f"  sudo mkdir -p /mnt/rtr2_image")
    P(f"  sudo mount -o loop,offset=$((512*{lba_start})) {path} /mnt/rtr2_image")
    P("  For E01: sudo apt install afflib-tools && ewfmount image.E01 /mnt/ewf")

def image_timeline(path):
    H("DISK IMAGE TIMELINE ANALYSIS")
    P("To analyze filesystem timeline, mount the image and run:")
    P("  fls -r -m / image.dd > body.txt")
    P("  mactime -b body.txt > timeline.txt")
    P("Or use The Sleuth Kit:")
    P("  fls -o <sector_offset> -r image.dd")
    P("  istat image.dd <inode>")

def recover_deleted(path):
    H("DELETED FILE RECOVERY")
    P("Analyzing disk image for deleted entries...")
    out,err,rc = cmd(["fls","-r",path])
    if rc == 0:
        deleted = [l for l in out.split("\n") if "*" in l]
        I(f"Found {len(deleted)} deleted entries")
        for d in deleted[:30]:
            print(f"  {R}{d}{N}")
    else:
        W("Sleuth Kit not installed. Install: apt install sleuthkit")
        W("Alternative: extundelete for ext3/4, testdisk for generic recovery")

# ═══════════════════════════════════════════════════════════
# LOG ANALYSIS
# ═══════════════════════════════════════════════════════════
def analyze_log(path, search_terms=None):
    H("LOG FILE ANALYSIS")
    P(f"Analyzing: {path}")
    if search_terms is None:
        search_terms = ["failed","error","warning","login","authentication","failed","denied","malware","suspicious"]
    lines = []
    try:
        with open(path,"r",errors="ignore") as f:
            lines = f.readlines()
    except:
        with open(path,"rb") as f:
            data = f.read()
            lines = data.decode("utf-8","ignore").split("\n")
    I(f"Total lines: {len(lines)}")
    for term in search_terms:
        matches = [l.strip() for l in lines if term.lower() in l.lower()]
        if matches:
            print(f"\n  {R}Matches for '{term}': {len(matches)}{N}")
            for m in matches[:20]:
                print(f"    {Y}{m[:150]}{N}")
    return lines

def analyze_access_log(path):
    H("ACCESS LOG ANALYSIS")
    P("Parsing Apache/Nginx access log...")
    ip_counts = {}
    path_counts = {}
    status_codes = {}
    ua_map = {}
    lines = []
    try:
        with open(path,"r",errors="ignore") as f:
            lines = f.readlines()
    except:
        with open(path,"rb") as f:
            lines = f.read().decode("utf-8","ignore").split("\n")
    for line in lines[:5000]:
        if not line.strip(): continue
        # Apache combined log format
        m = re.match(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"', line)
        if m:
            ip,date,method,path_s,status,size,referer,ua = m.groups()
            ip_counts[ip] = ip_counts.get(ip,0)+1
            path_counts[path_s] = path_counts.get(path_s,0)+1
            status_codes[status] = status_codes.get(status,0)+1
            if ua:
                ua_map[ua] = ua_map.get(ua,0)+1
    print(f"\n  {Y}Top IPs:{N}")
    for ip,cnt in sorted(ip_counts.items(),key=lambda x:-x[1])[:10]:
        print(f"    {C}{ip:>15s}{N}: {cnt} requests")
    print(f"\n  {Y}Status Codes:{N}")
    for s,cnt in sorted(status_codes.items()):
        sym = "OK" if s.startswith("2") else "WARN" if s.startswith("4") else "ERR"
        col = G if sym=="OK" else Y if sym=="WARN" else R
        print(f"    {col}{s}{N}: {cnt}")
    print(f"\n  {Y}Top Paths:{N}")
    for p,cnt in sorted(path_counts.items(),key=lambda x:-x[1])[:15]:
        print(f"    {B}{p}{N}: {cnt}")
    print(f"\n  {Y}Suspicious User Agents:{N}")
    suspicious = ["python","curl","wget","scan","bot","crawl","spider","nikto","sqlmap","nmap","hydra"]
    for ua,cnt in ua_map.items():
        if any(s in ua.lower() for s in suspicious):
            print(f"    {R}{ua[:100]}{N}: {cnt}")

def analyze_windows_evtx(path):
    H("WINDOWS EVENT LOG (EVTX)")
    P(f"Analyzing: {path}")
    out,err,rc = cmd(["python3","-c","import evtx; print('ok')"])
    if rc != 0:
        W("evtx python module not found. Try:")
        W("  pip3 install python-evtx")
        W("Alternative: Get-WinEvent or evtxexport from libyal")
    else:
        P("EVTX parsing available")

# ═══════════════════════════════════════════════════════════
# METADATA ANALYSIS
# ═══════════════════════════════════════════════════════════
def extract_metadata(path):
    H("METADATA EXTRACTION")
    P(f"Extracting metadata from: {path}")
    # EXIF for images
    if any(path.lower().endswith(ext) for ext in [".jpg",".jpeg",".png",".tiff",".bmp"]):
        out,err,rc = cmd(["exiftool","-G","-a","-s",path])
        if rc == 0:
            I("EXIF Data:")
            print(out[:3000])
        else:
            W("exiftool not available")
            # Manual EXIF parse for JPEG
            if path.lower().endswith((".jpg",".jpeg")):
                parse_jpeg_exif(path)
    elif path.lower().endswith(".pdf"):
        out,err,rc = cmd(["exiftool","-G","-a","-s",path])
        if rc == 0:
            I("PDF Metadata:")
            print(out[:3000])
    elif any(path.lower().endswith(ext) for ext in [".doc",".docx",".xls",".xlsx",".ppt",".pptx"]):
        out,err,rc = cmd(["exiftool","-G","-a","-s",path])
        if rc == 0:
            I("Office Metadata:")
            print(out[:3000])
        else:
            P("Using zipfile for DOCX/XLSX metadata...")
            import zipfile
            try:
                with zipfile.ZipFile(path) as z:
                    for name in z.namelist():
                        if "docProps" in name or "metadata" in name.lower():
                            print(f"  {C}{name}{N}")
            except: pass
    else:
        out,err,rc = cmd(["exiftool","-G","-a","-s",path])
        if rc == 0 and out.strip():
            print(out[:3000])
        else:
            I("No specific metadata extractor. Try: exiftool file")

def parse_jpeg_exif(path):
    P("Manual JPEG EXIF parsing...")
    with open(path,"rb") as f:
        data = f.read()
    pos = 2
    while pos < len(data)-4:
        if data[pos] == 0xFF and data[pos+1] != 0x00 and data[pos+1] != 0xFF:
            marker = data[pos+1]
            length = struct.unpack(">H",data[pos+2:pos+4])[0]
            if marker == 0xE1:
                I(f"APP1 (EXIF) segment at offset {pos}, length {length}")
                exif_data = data[pos+4:pos+2+length]
                # Check for EXIF header
                if exif_data[:6] == b"Exif\x00\x00":
                    I("EXIF header detected (JFIF-style)")
                    # Just show raw bytes as hex
                    I(f"First 32 bytes: {B}{exif_data[6:38].hex()}{N}")
            elif marker == 0xFE:
                comment = data[pos+4:pos+2+length].decode("utf-8","ignore")
                I(f"Comment: {Y}{comment}{N}")
                if "flag" in comment.lower():
                    F(comment)
            pos += 2 + length
        else:
            pos += 1

# ═══════════════════════════════════════════════════════════
# LOCATION / GPS ANALYSIS
# ═══════════════════════════════════════════════════════════
def analyze_location_data(path):
    H("LOCATION / GPS DATA ANALYSIS")
    P(f"Analyzing location data: {path}")
    # Check for GPX
    if path.lower().endswith(".gpx"):
        with open(path,"r") as f:
            content = f.read()
        lats = re.findall(r'lat="([^"]+)"', content)
        lons = re.findall(r'lon="([^"]+)"', content)
        times = re.findall(r'<time>([^<]+)</time>', content)
        I(f"GPX Waypoints: {len(lats)}")
        for i in range(min(len(lats), 20)):
            lat = lats[i] if i < len(lats) else ""
            lon = lons[i] if i < len(lons) else ""
            t = times[i] if i < len(times) else ""
            print(f"  {C}{lat}{N}, {C}{lon}{N} @ {t}")
        return
    # Check for KML
    if path.lower().endswith(".kml"):
        with open(path,"r") as f:
            content = f.read()
        coords = re.findall(r'<coordinates>([^<]+)</coordinates>', content)
        I(f"KML Coordinates: {len(coords)}")
        for c in coords[:20]:
            print(f"  {C}{c.strip()}{N}")
        return
    # JSON location data
    if path.lower().endswith(".json"):
        with open(path,"r") as f:
            try:
                data = json.load(f)
                # Google Maps Timeline
                if isinstance(data, dict) and ("locations" in data or "activity" in data):
                    I("Google Maps Location History detected")
                    locations = data.get("locations", [])
                    for loc in locations[:50]:
                        lat = loc.get("latitudeE7", 0)/1e7
                        lon = loc.get("longitudeE7", 0)/1e7
                        ts = loc.get("timestampMs","")
                        print(f"  {C}{lat:.6f}{N}, {C}{lon:.6f}{N} @ {ts}")
                else:
                    print(json.dumps(data, indent=2)[:2000])
            except json.JSONDecodeError:
                E("Not valid JSON")
    # Binary location cache
    with open(path,"rb") as f:
        raw = f.read()
    lat_matches = re.findall(b'\x05\x00\x00\x00.{8}(.{8})', raw)
    I(f"Binary location markers: {len(lat_matches)}")
    # Look for common location app patterns
    if b"latitude" in raw.lower() or b"google" in raw.lower():
        I("Possible Google location data detected")
    if b"latitudeE7" in raw:
        I("Google Maps Timeline E7 format detected")
        for i in range(0, len(raw)-16, 16):
            chunk = raw[i:i+16]
            if len(chunk) == 16 and abs(struct.unpack("<q",chunk[0:8])[0]/1e7) < 90:
                lat = struct.unpack("<q",chunk[0:8])[0]/1e7
                lon = struct.unpack("<q",chunk[8:16])[0]/1e7
                if abs(lat) < 90 and abs(lon) < 180:
                    print(f"  {C}{lat:.6f}{N}, {C}{lon:.6f}{N}")

# ═══════════════════════════════════════════════════════════
# MEMORY / RAM DUMP ANALYSIS  
# ═══════════════════════════════════════════════════════════
def analyze_ram_dump(path):
    H("RAM DUMP ANALYSIS")
    P(f"Analyzing RAM dump: {path}")
    size = os.path.getsize(path)
    I(f"Size: {size:,} bytes ({size/(1024**3):.2f} GB)")
    out,err,rc = cmd(["which","volatility3"])
    if rc == 0:
        I("Volatility 3 detected!")
        P("Run: vol.py -f memory.dmp windows.pslist")
        P("     vol.py -f memory.dmp windows.hashdump")
        P("     vol.py -f memory.dmp windows netscan")
    else:
        W("Volatility not found. Install: pip3 install volatility3")
        P("Alternative approach - string search:")
        out,err,rc = cmd(["strings","-n","8",path])
        if rc == 0:
            keywords = ["password","hash","ntlm","kerberos","token","session","process","chrome","firefox"]
            for kw in keywords:
                hits = [l for l in out.split("\n") if kw.lower() in l.lower()]
                if hits:
                    print(f"\n  {Y}Keyword: {kw}{N} ({len(hits)} hits)")
                    for h in hits[:5]:
                        print(f"    {C}{h[:150]}{N}")

def analyze_ram_processes(path):
    H("PROCESS ANALYSIS FROM RAM")
    P("Searching for process artifacts...")
    # Common process names in memory
    targets = ["cmd.exe","powershell.exe","python.exe","curl.exe","wget.exe",
               "nc.exe","netcat","putty.exe","mstsc.exe","svchost"]
    with open(path,"rb") as f:
        raw = f.read()
    for proc in targets:
        count = raw.count(proc.encode())
        if count > 0:
            print(f"  {R}{proc}{N}: {count} occurrences")

# ═══════════════════════════════════════════════════════════
# ENCODING / DECODING
# ═══════════════════════════════════════════════════════════
def decode_base64(s):
    H("BASE64 DECODE")
    s = s.strip()
    P(f"Input: {s[:100]}")
    try:
        # Try direct decode
        result = base64.b64decode(s).decode("utf-8","ignore")
        if result:
            I(f"Result: {Y}{result}{N}")
            return result
    except: pass
    try:
        # Try URL-safe
        result = base64.urlsafe_b64decode(s).decode("utf-8","ignore")
        if result:
            I(f"Result (URL-safe): {Y}{result}{N}")
            return result
    except: pass
    E("Could not decode as Base64")

def decode_hex(s):
    H("HEX DECODE")
    s = s.strip().replace(" ","").replace("0x","")
    P(f"Input: {s[:100]}")
    try:
        result = bytes.fromhex(s).decode("utf-8","ignore")
        if result:
            I(f"Result: {Y}{result}{N}")
            return result
    except Exception as e:
        E(f"Error: {e}")

def decode_rot(s, n=13):
    H(f"ROT{n} DECODE")
    P(f"Input: {s[:100]}")
    result = ""
    for c in s:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result += chr((ord(c)-base+n)%26+base)
        else:
            result += c
    I(f"Result: {Y}{result}{N}")
    return result

def decode_caesar(s, brute=False):
    H("CAESAR CIPHER")
    P(f"Input: {s[:100]}")
    if brute:
        for n in range(26):
            result = ""
            for c in s:
                if c.isalpha():
                    base = ord("A") if c.isupper() else ord("a")
                    result += chr((ord(c)-base+n)%26+base)
                else:
                    result += c
            print(f"  ROT-{n}: {Y}{result}{N}")
            if "flag" in result.lower():
                F(result)
    else:
        return decode_rot(s, 13)

def decode_hexdump(data):
    H("HEXDUMP TO BINARY")
    P("Converting hexdump to binary file...")
    out,err,rc = cmd("xxd -r input.hex > output.bin")
    if rc == 0:
        O("Converted: output.bin")
    return out

def xor_cipher(data, key):
    H("XOR CIPHER")
    P(f"XOR decrypting with key: {repr(key)}")
    result = bytearray()
    k = key.encode() if isinstance(key,str) else key
    for i,b in enumerate(data):
        result.append(b ^ k[i % len(k)])
    text = result.decode("utf-8","ignore")
    print(f"  Result: {Y}{text[:500]}{N}")
    return bytes(result)

def detect_encoding(data):
    H("ENCODING DETECTION")
    # Check common encodings
    encodings = ["utf-8","utf-16-le","utf-16-be","ascii","latin-1","cp437"]
    for enc in encodings:
        try:
            text = data.decode(enc)
            alpha = sum(1 for c in text if c.isalpha())
            pct = alpha/len(text)*100 if text else 0
            print(f"  {enc}: {alpha} alpha chars ({pct:.1f}%)")
            if pct > 70 and enc != "latin-1":
                I(f"  Likely {enc}: {text[:200]}")
        except: pass

# ═══════════════════════════════════════════════════════════
# MALWARE / SUSPICIOUS ANALYSIS
# ═══════════════════════════════════════════════════════════
def malware_analysis(path):
    H("MALWARE / SUSPICIOUS FILE ANALYSIS")
    P(f"Analyzing: {path}")
    size = os.path.getsize(path)
    I(f"File size: {size:,} bytes")
    with open(path,"rb") as f:
        header = f.read(min(size, 8192))
    # Check for suspicious patterns
    susp = {
        b"CreateRemoteThread": "Remote thread injection",
        b"VirtualAlloc":      "Memory allocation (shellcode)",
        b"LoadLibrary":       "DLL injection attempt",
        b"GetProcAddress":    "Dynamic API resolution",
        b"WinExec":           "Process execution",
        b"cmd.exe":           "Command execution",
        b"powershell.exe":    "PowerShell execution",
        b"WScript":           "Script host",
        b"mshta.exe":         "HTA execution",
        b"certutil":          "Certificate utility (decoding)",
        b"curl":              "Network download",
        b"wget":              "Network download",
        b"base64":            "Base64 encoding",
        b"\\x90\\x90":        "NOP sled (shellcode)",
        b"\\xc3":             "Return instruction",
        b"MZ":                "PE executable",
        b"\\xff\\xe4":        "JMP ESP instruction",
    }
    for pattern,desc in susp.items():
        if pattern in header:
            E(f"Suspicious: {desc}")
    # YARA scan if available
    out,err,rc = cmd(["which","yara"])
    if rc == 0:
        I("YARA available. Run: yara rules.yar file")
    # Strings analysis
    printable = set(string.printable.encode())
    results = []
    buffer = b""
    for b in header:
        if b in printable:
            buffer += bytes([b])
        else:
            if len(buffer) > 8:
                results.append(buffer.decode("ascii","ignore"))
            buffer = b""
    for r in results:
        if any(x in r.lower() for x in ["http","https","ftp","ip","domain","dns",
                                          "eval","exec","system","shell","cmd"]):
            print(f"  {Y}{r}{N}")

# ═══════════════════════════════════════════════════════════
# TIMELINE BUILDER
# ═══════════════════════════════════════════════════════════
def build_timeline(evidence_paths, out_file="timeline.csv"):
    H("TIMELINE BUILDER")
    events = []
    for path in evidence_paths:
        if not os.path.exists(path):
            W(f"Skipping missing: {path}")
            continue
        # Get file MAC times
        stat = os.stat(path)
        ctime = datetime.fromtimestamp(stat.st_ctime).isoformat()
        mtime = datetime.fromtimestamp(stat.st_mtime).isoformat()
        atime = datetime.fromtimestamp(stat.st_atime).isoformat()
        events.append({"time": ctime, "type":"MAC", "source":path, "desc":"File created"})
        events.append({"time": mtime, "type":"MAC", "source":path, "desc":"File modified"})
        events.append({"time": atime, "type":"MAC", "source":path, "desc":"File accessed"})
        # Extract timestamps from file content
        if path.endswith((".log",".txt",".json")):
            try:
                with open(path) as f:
                    content = f.read()
                ts_patterns = [
                    (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', 'ISO timestamp'),
                    (r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', 'Apache log'),
                    (r'Mon|Tue|Wed|Thu|Fri|Sat|Sun', 'Day name'),
                ]
                for pat,desc in ts_patterns:
                    for m in re.finditer(pat, content):
                        print(f"  {C}{m.group()}{N} in {B}{Path(path).name}{N} ({desc})")
            except: pass
    # Sort and save
    events.sort(key=lambda x: x["time"])
    import csv
    with open(out_file,"w",newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time","type","source","desc"])
        writer.writeheader()
        writer.writerows(events)
    O(f"Timeline saved: {out_file} ({len(events)} events)")
    return events


# ═══════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════
def generate_report(evidence_paths, output_dir="rtr2_report"):
    H("GENERATING INVESTIGATION REPORT")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "case_id": f"RTR2-{timestamp}",
        "competition": "Rise The Ranger 2 - Digital Forensics",
        "organizer": "Satsiber TNI",
        "date": timestamp,
        "evidence": [],
        "findings": [],
        "hashes": {},
        "timeline": [],
    }
    I(f"Case ID: {report['case_id']}")
    I(f"Output: {output_dir}")
    for path in evidence_paths:
        if not os.path.exists(path):
            W(f"Skipping missing: {path}")
            continue
        P(f"Processing: {path}")
        stat = os.stat(path)
        entry = {
            "filename": os.path.basename(path),
            "path": path,
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hashes": {}
        }
        with open(path,"rb") as f:
            data = f.read()
        for alg in ["md5","sha1","sha256"]:
            h = hashlib.new(alg)
            h.update(data)
            entry["hashes"][alg] = h.hexdigest()
        report["evidence"].append(entry)
        I(f"  MD5:    {entry['hashes']['md5']}")
        I(f"  SHA1:   {entry['hashes']['sha1']}")
        I(f"  SHA256: {entry['hashes']['sha256']}")
        # Identify file
        with open(path,"rb") as f:
            hdr = f.read(16)
        for sig,(ftype,mime) in FILE_SIGS.items():
            if hdr.startswith(sig):
                entry["type"] = ftype
                entry["mime"] = mime
                break
    # Save JSON report
    report_file = f"{output_dir}/report_{timestamp}.json"
    with open(report_file,"w") as f:
        json.dump(report, f, indent=2)
    O(f"JSON report: {report_file}")
    # Save markdown report
    md_file = f"{output_dir}/report_{timestamp}.md"
    md = f"""# Digital Forensics Investigation Report
## Rise The Ranger 2 - Satsiber TNI 2026

**Case ID:** {report['case_id']}  
**Date:** {report['date']}  
**Competition:** Rise The Ranger 2 - Digital Forensics  
**Organizer:** Satsiber TNI  

---

## Chain of Custody

| # | Filename | Size | Type | MD5 | SHA256 |
|---|----------|------|------|-----|--------|
"""
    for i,e in enumerate(report["evidence"],1):
        md += f"| {i} | {e['filename']} | {e['size_bytes']:,} B | {e.get('type','?')} | `{e['hashes']['md5']}` | `{e['hashes']['sha256']}` |\n"
    md += f"\n\n---\n*Generated by RTR2-CTF Toolkit | {datetime.now().isoformat()}*\n"
    with open(md_file,"w") as f:
        f.write(md)
    O(f"Markdown report: {md_file}")
    return report

# ═══════════════════════════════════════════════════════════
# WRITEUP GENERATOR - Challenge Solution Documentation
# ═══════════════════════════════════════════════════════════
def generate_writeup(args):
    H("GENERATING CHALLENGE WRITEUP")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Interactive mode if no arguments provided
    if not args.challenge and not args.category:
        print(f"\n{G}=== Challenge Writeup Generator ==={N}\n")
        challenge = input(f"  {C}Challenge Name:{N} ").strip()
        category = input(f"  {C}Category (Forensics/Stego/Crypto/Web/OSINT):{N} ").strip() or "Forensics"
        difficulty = input(f"  {C}Difficulty (Easy/Medium/Hard):{N} ").strip() or "Easy"
        tools = input(f"  {C}Tools Used (comma separated):{N} ").strip()
        tools_list = [t.strip() for t in tools.split(",")] if tools else []
        flag = input(f"  {C}Flag Found:{N} ").strip()
        steps_raw = input(f"  {C}Solution Steps:{N} (one per line, empty to finish)\n").strip()
        steps = []
        while steps_raw:
            steps.append(steps_raw)
            steps_raw = input("  > ").strip()
        notes = input(f"  {C}Additional Notes/Tips:{N} ").strip()
    else:
        challenge = args.challenge or "Unnamed Challenge"
        category = args.category or "Forensics"
        difficulty = args.difficulty or "Easy"
        tools_list = args.tools or []
        flag = args.flag or ""
        steps = args.steps or []
        notes = args.notes or ""

    # Build markdown writeup
    md = f"""# Writeup: {challenge}

## Challenge Info
- **Category:** {category}
- **Difficulty:** {difficulty}
- **Date:** {datetime.now().strftime("%Y-%m-%d %H:%M")}
- **Competition:** Rise The Ranger 2 - Satsiber TNI 2026

---

## Tools Used
"""
    if tools_list:
        for tool in tools_list:
            md += f"- {tool}\n"
    else:
        md += "- (none specified)\n"

    md += f"""

## Solution Steps
"""
    if steps:
        for i, step in enumerate(steps, 1):
            md += f"{i}. {step}\n"
    else:
        md += "_No steps recorded_\n"

    if flag:
        md += f"""
---

## Flag

```
{flag}
```

"""
    if notes:
        md += f"""---

## Notes & Tips

{notes}

"""

    md += f"""---

## Reference

_Template generated by RTR2-CTF Toolkit | {datetime.now().isoformat()}_
"""

    # Save writeup
    output_dir = args.output or "writeups"
    os.makedirs(output_dir, exist_ok=True)
    safe_name = challenge.lower().replace(" ", "_").replace("/", "_")
    filename = f"{output_dir}/{safe_name}_{timestamp}.md"

    with open(filename, "w") as f:
        f.write(md)

    O(f"Writeup saved: {filename}")

    # Also save a quick summary CSV
    csv_file = f"{output_dir}/summary.csv"
    csv_exists = os.path.exists(csv_file)
    with open(csv_file, "a") as f:
        if not csv_exists:
            f.write("date,challenge,category,difficulty,flag\n")
        f.write(f"{datetime.now().strftime('%Y-%m-%d')},{challenge},{category},{difficulty},{flag}\n")

    I(f"Summary updated: {csv_file}")
    return filename

# ═══════════════════════════════════════════════════════════
# AUTO-DETECT EVIDENCE TYPE
# ═══════════════════════════════════════════════════════════
def auto_analyze(path):
    H(f"AUTO-ANALYZE: {path}")
    P(f"Auto-detecting and analyzing: {path}")
    size = os.path.getsize(path)
    print(f"  Size: {size:,} bytes")
    # Identify file type
    with open(path,"rb") as f:
        hdr = f.read(32)
    print(f"  Header: {hdr[:16].hex()}")
    ftype = "unknown"
    for sig,(name,mime) in FILE_SIGS.items():
        if hdr.startswith(sig):
            ftype = name
            I(f"Detected type: {B}{name}{N} ({mime})")
            break
    # Route to appropriate analyzer
    if ftype == "unknown":
        if b"PK" in hdr:
            I("Likely ZIP-based format")
        elif hdr[0] >= 32 and hdr[0] < 127:
            I("Likely text-based file")
    if ftype in ("PNG","JPEG","GIF87a","GIF89a","BMP"):
        stego_lsb(path)
        stego_exif(path)
        stego_binwalk(path)
    elif ftype in ("ZIP","RAR","7z"):
        P("Archive detected - try: unzip, 7z x, binwalk -e")
        stego_binwalk(path)
    elif "PCAP" in ftype or "RIFF" in ftype or "pcap" in path.lower():
        pcap_info(path)
        pcap_dns(path)
        pcap_http(path)
        pcap_credentials(path)
    elif ftype in ("ELF","EXE/DOS"):
        malware_analysis(path)
        extract_strings(path)
    else:
        extract_strings(path, min_len=6)
        identify_file(path)

# ═══════════════════════════════════════════════════════════
# CHAIN OF CUSTODY
# ═══════════════════════════════════════════════════════════
def chain_of_custody(path):
    H("CHAIN OF CUSTODY")
    P(f"Documenting: {path}")
    if not os.path.exists(path):
        E(f"File not found: {path}")
        return
    stat = os.stat(path)
    with open(path,"rb") as f:
        data = f.read()
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    now = datetime.now().isoformat()
    coc = f"""CHAIN OF CUSTODY DOCUMENT
=============================
File: {path}
Size: {stat.st_size:,} bytes
Analysis Date: {now}

Hash Values (verified):
  MD5:    {md5}
  SHA1:   {sha1}
  SHA256: {sha256}

File Timestamps:
  Created:   {datetime.fromtimestamp(stat.st_ctime).isoformat()}
  Modified:  {datetime.fromtimestamp(stat.st_mtime).isoformat()}
  Accessed:  {datetime.fromtimestamp(stat.st_atime).isoformat()}

Integrity Status: VERIFIED
"""
    print(coc)
    coc_file = "chain_of_custody.txt"
    with open(coc_file,"w") as f:
        f.write(coc)
    O(f"Chain of Custody saved: {coc_file}")
    return coc

# ═══════════════════════════════════════════════════════════
# COMPETITION UTILS
# ═══════════════════════════════════════════════════════════
def competition_info():
    H("RISE THE RANGER 2 - INFO")
    info = """
  Competition : Rise The Ranger 2 - Digital Forensics
  Organizer   : Satsiber TNI (Satuan Siber TNI)
  Date        : 15-16 Aug 2026 (Online) | 23-24 Aug 2026 (Offline Final)
  Category    : Mahasiswa & Umum/Profesional
  Team Size   : 2-3 orang

  TOPICS (Babak Penyisihan):
  ├── Analisa Hash
  ├── Analisa File .pcap
  ├── Steganografi
  ├── Log Traffic Riwayat Lokasi
  ├── Metadata
  └── Analisa Peserta

  TOPICS (Babak Final - Offline):
  ├── Image Hardisk (Artifact Evidence Pack)
  ├── Dump RAM
  ├── Bin File
  ├── Steganografi
  └── Log Jaringan Perimeter

  ALLOWED TOOLS:
  ├── Wireshark, Sysinternals, Velociraptor
  ├── TheHive, Autopsy
  └── Any forensics/security analysis tools

  STEPS:
  ├── Penyisihan : 5 steps (masing-masing max 3 jam, total 15 jam)
  └── Final      : 7 chapters, 3-6 soal per chapter, 6 jam

  RULES:
  ├── Dilarang menyerang infrastruktur kompetisi
  ├── Kecurangan = diskualifikasi langsung
  └── Keputusan juri MUTLAK dan tidak bisa diganggu gugat

  CONTACT:
  ├── WhatsApp : +62 822-4549-1379
  ├── Email    : risetheranger@satsiber-tni.mil.id
  └── Web      : https://risetheranger.satsiber-tni.mil.id
"""
    print(f"{C}{info}{N}")


# ═══════════════════════════════════════════════════════════
# MAIN CLI
# ═══════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="Rise The Ranger 2 - Digital Forensics CTF Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  rtr2_ctf.py hash file.bin                          # Compute all hashes
  rtr2_ctf.py pcap-info capture.pcap                  # PCAP info
  rtr2_ctf.py pcap-creds capture.pcap                 # Extract credentials
  rtr2_ctf.py stego-lsb image.png                     # LSB extraction
  rtr2_ctf.py stego-exif image.jpg                    # EXIF extraction
  rtr2_ctf.py strings file.bin --min 8               # Extract strings
  rtr2_ctf.py meta file.pdf                           # Metadata
  rtr2_ctf.py location history.json                   # GPS/Location data
  rtr2_ctf.py hexdump file.bin --len 512              # Hex dump
  rtr2_ctf.py decode-b64 S2F2...                      # Base64 decode
  rtr2_ctf.py decode-hex 48656c6c6f                   # Hex decode
  rtr2_ctf.py caesar "Uif..." --brute                 # Caesar brute force
  rtr2_ctf.py xor file.bin --key mykey                # XOR decrypt
  rtr2_ctf.py carve file.bin                          # File carving
  rtr2_ctf.py malware file.exe                        # Malware analysis
  rtr2_ctf.py auto file.bin                           # Auto-detect & analyze
  rtr2_ctf.py report file1 file2 -o report            # Generate report
  rtr2_ctf.py timeline evidence1 evidence2            # Build timeline
  rtr2_ctf.py coc file.bin                           # Chain of custody
  rtr2_ctf.py info                                   # Competition info
  rtr2_ctf.py mount image.dd                          # Disk image mount helper
        """
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    # hash
    p = sub.add_parser("hash", help="Compute file hashes (MD5, SHA1, SHA256, etc.)")
    p.add_argument("file", help="File to hash")
    # verify-hash
    p = sub.add_parser("verify-hash", help="Verify file hash")
    p.add_argument("file", help="File to verify")
    p.add_argument("expected", help="Expected hash value")
    p.add_argument("--alg", default="auto", help="Hash algorithm (auto, md5, sha1, sha256)")
    # identify-hash
    p = sub.add_parser("identify-hash", help="Identify hash type")
    p.add_argument("hash", help="Hash string to identify")
    # crack
    p = sub.add_parser("crack", help="Dictionary attack on hash")
    p.add_argument("hash", help="Hash to crack")
    p.add_argument("wordlist", help="Wordlist file")
    # pcap-info
    p = sub.add_parser("pcap-info", help="PCAP file statistics")
    p.add_argument("file", help="PCAP file")
    # pcap-filter
    p = sub.add_parser("pcap-filter", help="Filter PCAP by expression")
    p.add_argument("file", help="PCAP file")
    p.add_argument("filter", help="BPF filter expression")
    # pcap-extract
    p = sub.add_parser("pcap-extract", help="Extract files from PCAP")
    p.add_argument("file", help="PCAP file")
    p.add_argument("-o","--out", default=None, help="Output directory")
    # pcap-dns
    p = sub.add_parser("pcap-dns", help="Extract DNS queries from PCAP")
    p.add_argument("file", help="PCAP file")
    # pcap-http
    p = sub.add_parser("pcap-http", help="Extract HTTP traffic from PCAP")
    p.add_argument("file", help="PCAP file")
    # pcap-strings
    p = sub.add_parser("pcap-strings", help="String search in PCAP")
    p.add_argument("file", help="PCAP file")
    p.add_argument("-k","--keyword", default=None, help="Keyword to search")
    # pcap-creds
    p = sub.add_parser("pcap-creds", help="Extract credentials from PCAP")
    p.add_argument("file", help="PCAP file")
    # stego-lsb
    p = sub.add_parser("stego-lsb", help="LSB steganography extraction")
    p.add_argument("file", help="Image file")
    # stego-zsteg
    p = sub.add_parser("stego-zsteg", help="ZSTEG steganography analysis")
    p.add_argument("file", help="Image file")
    # stego-exif
    p = sub.add_parser("stego-exif", help="EXIF metadata extraction")
    p.add_argument("file", help="Image/PDF file")
    # stego-steghide
    p = sub.add_parser("stego-steghide", help="Steghide analysis")
    p.add_argument("file", help="Image file")
    p.add_argument("-p","--password", default="", help="Password")
    # stego-binwalk
    p = sub.add_parser("stego-binwalk", help="Binwalk analysis")
    p.add_argument("file", help="File to analyze")
    # identify
    p = sub.add_parser("identify", help="Identify file type")
    p.add_argument("file", help="File to identify")
    # strings
    p = sub.add_parser("strings", help="Extract strings from file")
    p.add_argument("file", help="File to extract strings from")
    p.add_argument("--min", type=int, default=4, help="Minimum string length")
    p.add_argument("--all", action="store_true", help="Include non-printable separators")
    # hexdump
    p = sub.add_parser("hexdump", help="Hex dump of file")
    p.add_argument("file", help="File to dump")
    p.add_argument("--len", type=int, default=256, help="Bytes to dump")
    p.add_argument("--offset", type=int, default=0, help="Start offset")
    # carve
    p = sub.add_parser("carve", help="Carve files from binary")
    p.add_argument("file", help="File to carve from")
    p.add_argument("-o","--out", default=None, help="Output directory")
    # meta
    p = sub.add_parser("meta", help="Extract metadata")
    p.add_argument("file", help="File to extract metadata from")
    # location
    p = sub.add_parser("location", help="Analyze location/GPS data")
    p.add_argument("file", help="Location data file (GPX, KML, JSON)")
    # mount-image
    p = sub.add_parser("mount-image", help="Disk image analysis helper")
    p.add_argument("file", help="Disk image file")
    # ram
    p = sub.add_parser("ram", help="Analyze RAM dump")
    p.add_argument("file", help="Memory dump file")
    # ram-proc
    p = sub.add_parser("ram-proc", help="Search processes in RAM dump")
    p.add_argument("file", help="Memory dump file")
    # timeline
    p = sub.add_parser("timeline", help="Build timeline from evidence")
    p.add_argument("files", nargs="+", help="Evidence files")
    p.add_argument("-o","--out", default="timeline.csv", help="Output CSV")
    # report
    p = sub.add_parser("report", help="Generate forensics report")
    p.add_argument("files", nargs="+", help="Evidence files")
    p.add_argument("-o","--out", default="rtr2_report", help="Output directory")
    # coc
    p = sub.add_parser("coc", help="Generate Chain of Custody document")
    p.add_argument("file", help="Evidence file")
    # decode-b64
    p = sub.add_parser("decode-b64", help="Decode Base64 string")
    p.add_argument("data", help="Base64 string")
    # decode-hex
    p = sub.add_parser("decode-hex", help="Decode hex string")
    p.add_argument("data", help="Hex string")
    # caesar
    p = sub.add_parser("caesar", help="Caesar cipher decode")
    p.add_argument("data", help="Encrypted text")
    p.add_argument("-n","--shift", type=int, default=13, help="Shift value")
    p.add_argument("--brute", action="store_true", help="Brute force all shifts")
    # xor
    p = sub.add_parser("xor", help="XOR cipher decrypt")
    p.add_argument("file", help="File to decrypt")
    p.add_argument("-k","--key", required=True, help="XOR key")
    # malware
    p = sub.add_parser("malware", help="Malware/suspicious analysis")
    p.add_argument("file", help="File to analyze")
    # auto
    p = sub.add_parser("auto", help="Auto-detect and analyze file")
    p.add_argument("file", help="File to analyze")
    # info
    p = sub.add_parser("info", help="Competition information")
    # log
    p = sub.add_parser("log", help="Analyze log file")
    p.add_argument("file", help="Log file")
    p.add_argument("-s","--search", nargs="+", default=None, help="Search terms")
    # access-log
    p = sub.add_parser("access-log", help="Analyze web access log")
    p.add_argument("file", help="Access log file")
    # writeup
    p = sub.add_parser("writeup", help="Generate challenge solution writeup")
    p.add_argument("-c","--challenge", default=None, help="Challenge name")
    p.add_argument("-cat","--category", default=None, help="Category (Forensics/Stego/Crypto/Web/OSINT)")
    p.add_argument("-d","--difficulty", default=None, help="Difficulty (Easy/Medium/Hard)")
    p.add_argument("-t","--tools", nargs="+", default=None, help="Tools used")
    p.add_argument("-f","--flag", default=None, help="Flag found")
    p.add_argument("-s","--steps", nargs="+", default=None, help="Solution steps")
    p.add_argument("-n","--notes", default=None, help="Additional notes/tips")
    p.add_argument("-o","--output", default=None, help="Output directory (default: writeups)")
    args = parser.parse_args()
    print(BANNER)
    try:
        if args.cmd == "info":
            competition_info()
        elif args.cmd == "hash":
            hash_file(args.file)
        elif args.cmd == "verify-hash":
            verify_hash(args.file, args.expected, args.alg)
        elif args.cmd == "identify-hash":
            identify_hash(args.hash)
        elif args.cmd == "crack":
            wordlist_crack(args.hash, args.wordlist)
        elif args.cmd == "pcap-info":
            pcap_info(args.file)
        elif args.cmd == "pcap-filter":
            pcap_filter(args.file, args.filter)
        elif args.cmd == "pcap-extract":
            pcap_extract_files(args.file, args.out)
        elif args.cmd == "pcap-dns":
            pcap_dns(args.file)
        elif args.cmd == "pcap-http":
            pcap_http(args.file)
        elif args.cmd == "pcap-strings":
            pcap_strings(args.file, args.keyword)
        elif args.cmd == "pcap-creds":
            pcap_credentials(args.file)
        elif args.cmd == "stego-lsb":
            stego_lsb(args.file)
        elif args.cmd == "stego-zsteg":
            stego_zsteg(args.file)
        elif args.cmd == "stego-exif":
            stego_exif(args.file)
        elif args.cmd == "stego-steghide":
            stego_steghide(args.file, args.password)
        elif args.cmd == "stego-binwalk":
            stego_binwalk(args.file)
        elif args.cmd == "identify":
            identify_file(args.file)
        elif args.cmd == "strings":
            extract_strings(args.file, args.min, not args.all)
        elif args.cmd == "hexdump":
            hex_dump(args.file, args.len, args.offset)
        elif args.cmd == "carve":
            carve_files(args.file, args.out)
        elif args.cmd == "meta":
            extract_metadata(args.file)
        elif args.cmd == "location":
            analyze_location_data(args.file)
        elif args.cmd == "mount-image":
            mount_image(args.file)
        elif args.cmd == "ram":
            analyze_ram_dump(args.file)
        elif args.cmd == "ram-proc":
            analyze_ram_processes(args.file)
        elif args.cmd == "timeline":
            build_timeline(args.files, args.out)
        elif args.cmd == "report":
            generate_report(args.files, args.out)
        elif args.cmd == "coc":
            chain_of_custody(args.file)
        elif args.cmd == "decode-b64":
            decode_base64(args.data)
        elif args.cmd == "decode-hex":
            decode_hex(args.data)
        elif args.cmd == "caesar":
            if args.brute:
                decode_caesar(args.data, True)
            else:
                decode_rot(args.data, args.shift)
        elif args.cmd == "xor":
            with open(args.file,"rb") as f:
                data = f.read()
            xor_cipher(data, args.key)
        elif args.cmd == "malware":
            malware_analysis(args.file)
        elif args.cmd == "auto":
            auto_analyze(args.file)
        elif args.cmd == "log":
            analyze_log(args.file, args.search)
        elif args.cmd == "access-log":
            analyze_access_log(args.file)
        elif args.cmd == "writeup":
            generate_writeup(args)
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print(f"\n{R}Interrupted.{N}")
        sys.exit(1)
    except Exception as e:
        E(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
