import pyshark
from collections import Counter, defaultdict
from datetime import datetime
from rich.progress import track
from statistics import mean
import matplotlib.pyplot as plt
import pandas as pd


class capture_analyzer:

    def __init__(self, file_path, filter=None):
        self.file_path_ = file_path
        self.pcap_ = pyshark.FileCapture(file_path, display_filter=filter, keep_packets=False)
        self.sessions_ = defaultdict(set)
        self.submits_ = {}
        self.submits_resp_ = {}

    def close(self):
        self.pcap_.close()

    def analyze_pcab(self):
        protocol_counter = Counter()
        timestamps = []
        packet_count = 0

        for pkt in track(self.pcap_, description="processing packets"):
            try:
                protocol = pkt.highest_layer
                timestamp = float(pkt.sniff_timestamp)
                protocol_counter[protocol] += 1
                timestamps.append(timestamp)
                packet_count += 1
                cmd_type = pkt.smpp.command_id.showname_value.lower()
                seq_num = pkt.smpp.sequence_number
                timestamp = float(pkt.sniff_timestamp)

                if 'bind_' in cmd_type and 'resp' not in cmd_type:
                    src_ip = pkt.ip.src
                    src_port = pkt.tcp.srcport
                    system_id = pkt.smpp.system_id
                    target_addr = f"{src_ip}:{src_port}"
                    self.sessions_[system_id].add(target_addr)

                if 'submit_sm' in cmd_type and 'resp' not in cmd_type:
                    self.submits_[seq_num] = timestamp

                elif 'submit_sm - resp' in cmd_type:
                    self.submits_resp_[seq_num] = timestamp

            except AttributeError:
                continue

        start_time = datetime.fromtimestamp(min(timestamps))
        end_time = datetime.fromtimestamp(max(timestamps))
        duration = end_time - start_time

        # Match requests with responses
        response_times = []
        for seq in self.submits_:
            if seq in self.submits_resp_:
                delta = self.submits_resp_[seq] - self.submits_[seq]
                response_times.append(delta)

        unmatched = set(self.submits_) - set(self.submits_resp_)
        min_diff = min(response_times) if response_times else None
        max_diff = max(response_times) if response_times else None
        mean_diff = mean(response_times) if response_times else None

        # Generate summary
        summary = {
            "total_packets": packet_count,
            "packets_by_protocols": dict(protocol_counter),
            "connections_count": len(self.sessions_),
            "sessions_count": {k: len(v) for k, v in self.sessions_.items()},
            "submit_sm_count": len(self.submits_),
            "submit_sm_resp_count": len(self.submits_resp_),
            "unmatched_submit_sequences": list(unmatched),
            "matched_count": len(response_times),
            "min_response_time": min_diff,
            "max_response_time": max_diff,
            "avg_response_time": mean_diff,
            "Count Greater Than Mean Time Difference": sum(d > mean_diff for d in response_times),
            "Count Smaller Than Mean Time Difference": sum(d < mean_diff for d in response_times),
            "Count Less Than 0.003": sum(d < 0.003 for d in response_times),
            "Count Less Than 0.005": sum(d < 0.005 for d in response_times),
            "Count Less Than 0.010": sum(d < 0.010 for d in response_times),
            "Count Less Than 0.020": sum(d < 0.020 for d in response_times),
            "Count Less Than 0.030": sum(d < 0.030 for d in response_times),
            "Count Less Than 0.040": sum(d < 0.040 for d in response_times),
            "Count Less Than 0.050": sum(d < 0.050 for d in response_times),
            "Count Less Than 0.070": sum(d < 0.070 for d in response_times),
            "Count Less Than 0.090": sum(d < 0.090 for d in response_times),
            "Count Greater Than 1.000": sum(d > 1.000 for d in response_times),
            "Count Greater Than 1.500": sum(d > 1.500 for d in response_times),
            "10 largest_differences": sorted(response_times, reverse=True)[:10],
            "capture_duration": str(duration),
            "start_time": str(start_time),
            "end_time": str(end_time)
        }

        self.plot_response_distribution(summary)
        return summary

    def plot_response_distribution(self, summary):
        import matplotlib.pyplot as plt
        import pandas as pd

        stats_to_plot = {
            "Greater Than Mean": summary["Count Greater Than Mean Time Difference"],
            "Smaller Than Mean": summary["Count Smaller Than Mean Time Difference"],
            "< 0.003": summary["Count Less Than 0.003"],
            "< 0.005": summary["Count Less Than 0.005"],
            "< 0.010": summary["Count Less Than 0.010"],
            "< 0.020": summary["Count Less Than 0.020"],
            "< 0.030": summary["Count Less Than 0.030"],
            "< 0.040": summary["Count Less Than 0.040"],
            "< 0.050": summary["Count Less Than 0.040"],
            "< 0.070": summary["Count Less Than 0.040"],
            "< 0.090": summary["Count Less Than 0.040"],
            "> 1.000": summary["Count Greater Than 1.000"],
            "> 1.500": summary["Count Greater Than 1.500"]
        }

        df = pd.DataFrame(list(stats_to_plot.items()), columns=["Category", "Count"])

        plt.figure(figsize=(12, 6))
        bars = plt.bar(df["Category"], df["Count"], color='skyblue')
        plt.xticks(rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        mean_value = summary["avg_response_time"]
        plt.title(f"Response Time Distribution ( Mean Response Time = {mean_value:.6f} sec)", fontsize=14, fontweight='bold')
        plt.xlabel("Time Categories", fontsize=12)
        plt.ylabel("Count", fontsize=12)

        # Annotate bars
        for bar in bars:
            height = bar.get_height()
            plt.annotate(f'{height:,}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

        plt.tight_layout()
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # Save chart
        output_file = "response_time_distribution.png"
        plt.savefig(output_file, dpi=300)
        print(f"Chart saved to {output_file}")
        plt.close()

def main():
    file_path = "smpp_sample.pcap"
    analyzer = capture_analyzer(file_path, filter=None)

    try:
        summary = analyzer.analyze_pcab()
        for key, value in summary.items():
            print(f"{key}: {value}")
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()
