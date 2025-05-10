import pyshark
from collections import Counter
from datetime import datetime
from rich.progress import track

class capture_analyzer:

    def __init__(self, file_path, filter=None):
        self.file_path_ = file_path
        self.cap_ = pyshark.FileCapture(file_path, display_filter=filter, keep_packets=False)

    def close(self):
        self.cap_.close()

    def analyze_smpp_submit_sm(self):
        submit_sm_count = 0
        submit_sm_resp_count = 0
        submit_sequences = set()
        submit_resp_sequences = set()

        for pkt in track(self.cap_, description="Processing SMPP packets"):
            try:
                cmd_id = pkt.smpp.command_id.showname_value.lower()
                seq_num = pkt.smpp.sequence_number

                if 'submit_sm' in cmd_id and 'resp' not in cmd_id:
                    submit_sm_count += 1
                    submit_sequences.add(seq_num)

                elif 'submit_sm - resp' in cmd_id:
                    submit_sm_resp_count += 1
                    submit_resp_sequences.add(seq_num)
            except AttributeError:
                continue

        unmatched = submit_sequences - submit_resp_sequences

        return {
            "submit_sm_count": submit_sm_count,
            "submit_sm_resp_count": submit_sm_resp_count,
            "unmatched_submit_sequences": list(unmatched),
            "matched_count": len(submit_sequences & submit_resp_sequences),
        }

    def summarize_pcap(self):
        protocol_counter = Counter()
        timestamps = []
        packet_count = 0

        for pkt in track(self.cap_, description="Processing PCAP packets"):
            try:
                protocol = pkt.highest_layer
                timestamp = float(pkt.sniff_timestamp)
                protocol_counter[protocol] += 1
                timestamps.append(timestamp)
                packet_count += 1
            except Exception as e:
                continue

        if not timestamps:
            return {"Error": "No valid packets found in capture"}

        start_time = datetime.fromtimestamp(min(timestamps))
        end_time = datetime.fromtimestamp(max(timestamps))
        duration = end_time - start_time

        return {
            "Total Packets": packet_count,
            "Capture Duration": str(duration),
            "Start Time": str(start_time),
            "End Time": str(end_time),
            "Packets by Protocol": dict(protocol_counter)
        }

def main():
    file_path = "smpp_sample.pcap"
    analyzer = capture_analyzer(file_path, filter=None)

    try:
        print("====== SMPP Analysis ======")
        smpp_result = analyzer.analyze_smpp_submit_sm()
        for key, value in smpp_result.items():
            print(f"{key}: {value}")

        print("\n====== General PCAP Summary ======")
        summary = analyzer.summarize_pcap()
        for key, value in summary.items():
            print(f"{key}: {value}")
    finally:
        analyzer.close()

if __name__ == "__main__":
    main()