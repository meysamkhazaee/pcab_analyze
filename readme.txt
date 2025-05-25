# 📡 PCAP Packet Analyzer

A Python script to analyze SMPP or other protocol packets from a `.pcap` file and extract response metrics.

---

## 📦 Installation

Make sure you have Python 3 installed. Then set up a virtual environment and install the required packages:

```bash
python3 -m venv myenv
source myenv/bin/ctivate
pip install -r requirements.txt

## 📦 Usage

usage: python3 main.py [-h] --pcap_file PCAP_FILE --packet_type PACKET_TYPE [--filter FILTER]
main.py: error: the following arguments are required: --pcap_file, --packet_type

Analyze SMPP or other packet types in a PCAP file and expose response metrics.

positional arguments:
  --pcap_file     Path to the PCAP file (e.g., ./file.pcap)
  --packet_type   Packet type to analyze (e.g., submit_sm, deliver_sm)
  --filter        Filter specific keyword on packet

options:
  -h, --help    Show this help message and exit