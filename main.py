import argparse
from pathlib import Path
from capture_analyzer import capture_analyzer

def main():
    parser = argparse.ArgumentParser(description="PCAP Analysis Tool")
    parser.add_argument('--pcap_file', type=str, required=True, help='Path to the PCAP file (e.g., ./<file_name>.pcap)')
    parser.add_argument('--packet_type', type=str, required=True, help='Defines which packet types should be analyzed.')
    parser.add_argument('--filter', type=str, help='Optional filter on PCAP file', default=None)
    args = parser.parse_args()

    current_dir = Path(__file__).parent.resolve()
    file_path = current_dir / args.pcap_file

    if not file_path.exists():
        parser.error(f"PCAP file not found: {file_path}")
    if not file_path.is_file() or file_path.suffix.lower() != '.pcap':
        parser.error(f"Invalid PCAP file: {file_path}. Please provide a valid .pcap file.")

    analyzer = capture_analyzer(file_path=str(file_path), filter=args.filter)

    try:
        analyzer.analyze_pcab(packet_type=args.packet_type)
        analyzer.generate_summary_image()
        analyzer.plot_response_distribution_by_count()
        analyzer.plot_response_distribution_by_percentage()
        analyzer.plot_raw_response_times()
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()