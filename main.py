import argparse
from pathlib import Path
import sys
from capture_analyzer import capture_analyzer

def main():
    parser = argparse.ArgumentParser(description="PCAP Analysis Tool")
    parser.add_argument('--pcap_file', type=str, required=True, help='Path to the PCAP file (e.g., ./<file_name>.pcap)')
    parser.add_argument('--packet_type', type=str, required=True, help='Defines which packet types should be analyzed.')
    parser.add_argument('--filter', type=str, help='Optional filter on PCAP file', default=None)
    args = parser.parse_args()

    if getattr(sys, 'frozen', False):
        current_dir = Path(sys.executable).parent
    else:
        current_dir = Path(__file__).parent.resolve()

    pcap_name = Path(args.pcap_file).stem
    file_path = current_dir / f"{pcap_name}.pcap"

    if file_path.exists():
        final_pcap_path = file_path
    elif Path(args.pcap_file).exists():
        final_pcap_path = Path(args.pcap_file)
    else:
        parser.error(f"PCAP file not found in current dir or at path: {args.pcap_file}")

    analyzer = capture_analyzer(file_path=str(final_pcap_path), filter=args.filter)

    try:
        analyzer.analyze_pcab(packet_type=args.packet_type)
        analyzer.generate_summary_text()
        analyzer.plot_response_distribution_by_count()
        analyzer.plot_response_distribution_by_percentage()
        analyzer.plot_raw_response_times()
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()