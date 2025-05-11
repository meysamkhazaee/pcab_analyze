import argparse
import sys
from pathlib import Path
from capture_analyzer import capture_analyzer  # Assuming this is your module

def main():
    parser = argparse.ArgumentParser(description="SMPP PCAP Analysis Tool")
    parser.add_argument('--pcap_file', type=str, help='Path to the PCAP file (e.g., smpp_sample.pcap)', default='smpp_sample.pcap')
    parser.add_argument('--filter', type=str, help='Optional BPF filter string', default=None)
    args = parser.parse_args()

    current_dir = Path(__file__).parent.resolve()
    file_path = current_dir / args.pcap_file

    # Validate PCAP file path
    if not file_path.exists():
        parser.error(f"PCAP file not found: {file_path}")
    if not file_path.is_file() or file_path.suffix.lower() != '.pcap':
        parser.error(f"Invalid PCAP file: {file_path}. Please provide a valid .pcap file.")

    analyzer = capture_analyzer(str(file_path), filter=args.filter)

    try:
        analyzer.analyze_pcab()
        analyzer.generate_summary_image()
        analyzer.plot_response_distribution_by_count()
        analyzer.plot_response_distribution_by_percentage()
        analyzer.plot_raw_response_times()
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()