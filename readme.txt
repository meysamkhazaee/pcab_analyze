usage: python3 main.py [-h] --pcap_file PCAP_FILE --packet_type PACKET_TYPE [--filter FILTER]
main.py: error: the following arguments are required: --pcap_file, --packet_type

Analyze SMPP or other packet types in a PCAP file and expose response metrics.

positional arguments:
  --pcap_file     Path to the PCAP file (e.g., ./file.pcap)
  --packet_type   Packet type to analyze (e.g., submit_sm, deliver_sm)
  --filter        Filter specific keyword on packet

options:
  -h, --help    Show this help message and exit