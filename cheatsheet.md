# RTR2-CTF Quick Reference Card
# Rise The Ranger 2 - Digital Forensics

## Most Used Commands

| Task | Command |
|------|---------|
| Analyze ANY file | `python3 rtr2_ctf.py auto <file>` |
| Hash verification | `python3 rtr2_ctf.py hash <file>` |
| Extract strings | `python3 rtr2_ctf.py strings <file> --min 8` |
| PCAP credentials | `python3 rtr2_ctf.py pcap-creds <file>` |
| LSB stego | `python3 rtr2_ctf.py stego-lsb <image>` |
| Metadata | `python3 rtr2_ctf.py meta <file>` |
| Hex dump | `python3 rtr2_ctf.py hexdump <file> --len 512` |
| Chain of Custody | `python3 rtr2_ctf.py coc <file>` |
| Full report | `python3 rtr2_ctf.py report <files...>` |
| **Generate Writeup** | `python3 rtr2_ctf.py writeup` |

## Timeline Analysis

| Evidence Type | Tool | Command |
|---------------|------|---------|
| PCAP | tshark | `tshark -r file.pcap -Y "dns"` |
| PCAP | tshark | `tshark -r file.pcap -Y "http.request" -T fields -e http.host` |
| PCAP | tshark | `tshark -r file.pcap -z follow,tcp,ascii,0` |
| Image | exiftool | `exiftool -G -a -s file.jpg` |
| Image | binwalk | `binwalk -e file.bin` |
| Image | foremost | `foremost -i file.pcap -o carved/` |
| RAM | volatility | `vol.py -f mem.dmp windows.pslist` |
| Disk | fls | `fls -r -m / image.dd > body.txt && mactime -b body.txt` |
| Log | grep | `grep -iE "failed|error|warning" access.log` |

## Common Hash Patterns

| Hash | Length | Regex |
|------|--------|-------|
| MD5 | 32 hex | `^[a-f0-9]{32}$` |
| SHA1 | 40 hex | `^[a-f0-9]{40}$` |
| SHA256 | 64 hex | `^[a-f0-9]{64}$` |
| NTLM | 32 hex | `^[a-f0-9]{32}$` |
| bcrypt | 60 char | `^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$` |
| MD5crypt | 34 char | `^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$` |

## File Magic Bytes

| Type | Signature | Hex |
|------|-----------|-----|
| PNG | PNG image | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | JPEG image | `FF D8 FF` |
| PDF | PDF doc | `25 50 44 46` |
| ZIP | ZIP archive | `50 4B 03 04` |
| GZIP | GZIP | `1F 8B` |
| RAR | RAR archive | `52 61 72 21` |
| ELF | Linux executable | `7F 45 4C 46` |
| MZ | Windows EXE | `4D 5A` |
| 7z | 7-Zip | `37 7A BC AF 27 1C` |

## Steganography Checklist

- [ ] `stego-lsb` - Extract LSB from PNG/BMP
- [ ] `stego-exif` - Check EXIF comments (also look for flags in comments)
- [ ] `stego-steghide` - Try with empty password, then common passwords
- [ ] `stego-binwalk` - Look for embedded files
- [ ] `stego-zsteg` - Ruby gem for PNG LSBs
- [ ] Check image dimensions for anomalies (e.g., prime numbers)
- [ ] Check palette for unusual colors
- [ ] `strings --min 8` - Look for embedded text
- [ ] Check for double extensions (image.pdf, image.jpg.exe)
- [ ] Check file signature vs extension mismatch

## PCAP Investigation Priority

1. `pcap-creds` - Get credentials first (flag often in auth)
2. `pcap-dns` - Check for suspicious domains
3. `pcap-http` - HTTP requests, look for suspicious URIs
4. `pcap-filter` with `http.request.uri contains "admin"`
5. `pcap-strings -k password` - Direct password search
6. `pcap-extract` - Extract uploaded/downloaded files
7. `pcap-strings -k flag` - Search for flag strings

## Encoding Recognition

| Encoding | Identifier |
|----------|-----------|
| Base64 | A-Z, a-z, 0-9, +, /, = padding |
| Hex | Only 0-9, a-f |
| URL Encoded | %XX pattern |
| ROT13 | Caesar with shift=13 |
| Caesar | Text rotated by N positions |
| XOR | Repetitive pattern, try brute force keys |

## Flag Format Patterns

```
RTR2{...}
flag{...}
RTR{something}
ctf{...}
RTR2-CTF{...}
```

Search in:
- File strings
- Image comments / EXIF
- PCAP reassembled data
- Memory dump
- Log files
- Metadata
- LSB of images
