## Installation

```bash
# Main tool (Python 3 required)
chmod +x rtr2_ctf.py

# Install optional dependencies for full functionality
pip3 install pillow pypng

# Optional - for enhanced analysis
pip3 install volatility3
gem install zsteg

# System tools (Debian/Ubuntu)
sudo apt install wireshark-common tshark foremost binwalk \
  exiftool sleuthkit libimage-exiftool-perl steghide \
  testdisk python-evtx afflib-tools yara

# Kali Linux / Forensics distro - most tools already included
```

## Quick Start

```bash
# Show competition info
python3 rtr2_ctf.py info

# Analyze any evidence file (auto-detect type)
python3 rtr2_ctf.py auto evidence.bin

# Compute all hashes
python3 rtr2_ctf.py hash evidence.bin

# Identify hash type
python3 rtr2_ctf.py identify-hash <hash>

# Extract strings
python3 rtr2_ctf.py strings evidence.bin --min 8

# Hex dump
python3 rtr2_ctf.py hexdump evidence.bin --len 1024
```

## Topic-Based Commands

### Hash Analysis
```bash
rtr2_ctf.py hash file.bin                     # Compute MD5/SHA1/SHA256/...
rtr2_ctf.py verify-hash file.bin <hash>       # Verify file integrity
rtr2_ctf.py identify-hash <hash>              # Identify hash algorithm
rtr2_ctf.py crack <hash> wordlist.txt        # Dictionary attack
```

### PCAP / Network Analysis
```bash
rtr2_ctf.py pcap-info capture.pcap            # PCAP statistics
rtr2_ctf.py pcap-dns capture.pcap             # Extract DNS queries
rtr2_ctf.py pcap-http capture.pcap            # Extract HTTP traffic
rtr2_ctf.py pcap-creds capture.pcap           # Extract credentials
rtr2_ctf.py pcap-filter capture.pcap "tcp"   # Apply BPF filter
rtr2_ctf.py pcap-extract capture.pcap         # Extract files from PCAP
rtr2_ctf.py pcap-strings capture.pcap -k flag # Search strings
```

### Steganography
```bash
rtr2_ctf.py stego-lsb image.png               # LSB extraction
rtr2_ctf.py stego-exif image.jpg              # EXIF metadata
rtr2_ctf.py stego-steghide image.png          # Steghide
rtr2_ctf.py stego-steghide image.png -p pass  # With password
rtr2_ctf.py stego-binwalk image.png           # Binwalk analysis
rtr2_ctf.py stego-zsteg image.png             # ZSTEG (needs gem)
```

### Log / Traffic Analysis
```bash
rtr2_ctf.py log access.log                    # Analyze log file
rtr2_ctf.py access-log access.log             # Apache/Nginx log
rtr2_ctf.py location history.json             # GPS/Location data
```

### Metadata Analysis
```bash
rtr2_ctf.py meta file.pdf                     # PDF metadata
rtr2_ctf.py meta document.docx                # Office metadata
rtr2_ctf.py meta image.jpg                    # Image EXIF
rtr2_ctf.py identify file.bin                 # Identify file type
```

### Disk Image & Memory
```bash
rtr2_ctf.py mount-image disk.dd               # Disk image info + mount guide
rtr2_ctf.py ram memory.dmp                    # RAM dump analysis
rtr2_ctf.py ram-proc memory.dmp               # Search processes
rtr2_ctf.py carve disk.dd                     # Carve files from image
```

### Encoding / Decoding
```bash
rtr2_ctf.py decode-b64 S2F2ZmxhZ3t...         # Base64 decode
rtr2_ctf.py decode-hex 48656C6C6F             # Hex decode
rtr2_ctf.py caesar "Uif..." --brute           # Caesar brute force
rtr2_ctf.py xor file.bin -k mykey            # XOR decrypt
```

### Reporting & Documentation
```bash
rtr2_ctf.py coc evidence.bin                  # Chain of Custody
rtr2_ctf.py timeline evidence1 evidence2       # Build timeline
rtr2_ctf.py report evidence1 evidence2 -o out  # Full report
rtr2_ctf.py writeup                            # Generate challenge writeup (interactive)
rtr2_ctf.py writeup -c "Challenge Name" -f "FLAG{...}" -t tool1 tool2  # Quick writeup
```

### Malware Analysis
```bash
rtr2_ctf.py malware suspicious.exe            # Analyze suspicious file
rtr2_ctf.py strings suspicious.exe --min 8   # Extract strings
```
