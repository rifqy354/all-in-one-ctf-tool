FROM python:3.12-slim

LABEL maintainer="RTR2-CTF"
LABEL description="Rise The Ranger 2 Digital Forensics CTF Toolkit"

RUN apt-get update && apt-get install -y \
    wireshark-common tshark \
    foremost \
    binwalk \
    exiftool \
    sleuthkit \
    steghide \
    testdisk \
    yara \
    vim \
    curl \
    wget \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pillow volatility3 pypng

COPY rtr2_ctf.py /usr/local/bin/rtr2_ctf.py
COPY cheatsheet.md /usr/local/share/rtr2_cheatsheet.md
RUN chmod +x /usr/local/bin/rtr2_ctf.py

WORKDIR /workspace
ENTRYPOINT ["python3", "/usr/local/bin/rtr2_ctf.py"]
