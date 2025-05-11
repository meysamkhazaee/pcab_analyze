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
        self.summary_ = {}
        self.response_times_ = []

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
        self.response_times_ = []
        for seq in self.submits_:
            if seq in self.submits_resp_:
                delta = self.submits_resp_[seq] - self.submits_[seq]
                self.response_times_.append(delta)

        unmatched = set(self.submits_) - set(self.submits_resp_)
        min_diff = min(self.response_times_) if self.response_times_ else None
        max_diff = max(self.response_times_) if self.response_times_ else None
        mean_diff = mean(self.response_times_) if self.response_times_ else None

        # Generate summary
        total_matched = len(self.response_times_) or 1  # Avoid division by zero

        count_gt_mean = sum(d > mean_diff for d in self.response_times_)
        count_lt_mean = sum(d < mean_diff for d in self.response_times_)
        count_001 = sum(d < 0.001 for d in self.response_times_)
        count_002 = sum(d < 0.002 for d in self.response_times_)
        count_003 = sum(d < 0.003 for d in self.response_times_)
        count_004 = sum(d < 0.004 for d in self.response_times_)
        count_005 = sum(d < 0.005 for d in self.response_times_)
        count_010 = sum(d < 0.010 for d in self.response_times_)
        count_020 = sum(d < 0.020 for d in self.response_times_)
        count_030 = sum(d < 0.030 for d in self.response_times_)
        count_040 = sum(d < 0.040 for d in self.response_times_)
        count_050 = sum(d < 0.050 for d in self.response_times_)
        count_070 = sum(d < 0.070 for d in self.response_times_)
        count_090 = sum(d < 0.090 for d in self.response_times_)
        count_gt_1000 = sum(d > 1.000 for d in self.response_times_)
        count_gt_1500 = sum(d > 1.500 for d in self.response_times_)

        self.summary_ = {
            "total_packets": packet_count,
            "packets_by_protocols": dict(protocol_counter),
            "connections_count": len(self.sessions_),
            "sessions_count": {k: len(v) for k, v in self.sessions_.items()},
            "submit_sm_count": len(self.submits_),
            "submit_sm_resp_count": len(self.submits_resp_),
            "unmatched_submit_sequences": list(unmatched),
            "matched_count": len(self.response_times_),
            "min_response_time": min_diff,
            "max_response_time": max_diff,
            "avg_response_time": mean_diff,
            "Count Greater Than Mean Time Difference": count_gt_mean,
            "Percent Greater Than Mean Time Difference": round((count_gt_mean / total_matched) * 100, 2),
            "Count Smaller Than Mean Time Difference": count_lt_mean,
            "Percent Smaller Than Mean Time Difference": round((count_lt_mean / total_matched) * 100, 2),
            "Count Less Than 0.001": count_001,
            "Count Less Than 0.002": count_002,
            "Count Less Than 0.003": count_003,
            "Count Less Than 0.004": count_004,
            "Count Less Than 0.005": count_005,
            "Count Less Than 0.010": count_010,
            "Count Less Than 0.020": count_020,
            "Count Less Than 0.030": count_030,
            "Count Less Than 0.040": count_040,
            "Count Less Than 0.050": count_050,
            "Count Less Than 0.070": count_070,
            "Count Less Than 0.090": count_090,
            "Count Greater Than 1.000": count_gt_1000,
            "Count Greater Than 1.500": count_gt_1500,
            "Percent Less Than 0.001": round((count_001 / total_matched) * 100, 2),
            "Percent Less Than 0.002": round((count_002 / total_matched) * 100, 2),
            "Percent Less Than 0.003": round((count_003 / total_matched) * 100, 2),
            "Percent Less Than 0.004": round((count_004 / total_matched) * 100, 2),
            "Percent Less Than 0.005": round((count_005 / total_matched) * 100, 2),
            "Percent Less Than 0.010": round((count_010 / total_matched) * 100, 2),
            "Percent Less Than 0.020": round((count_020 / total_matched) * 100, 2),
            "Percent Less Than 0.030": round((count_030 / total_matched) * 100, 2),
            "Percent Less Than 0.040": round((count_040 / total_matched) * 100, 2),
            "Percent Less Than 0.050": round((count_050 / total_matched) * 100, 2),
            "Percent Less Than 0.070": round((count_070 / total_matched) * 100, 2),
            "Percent Less Than 0.090": round((count_090 / total_matched) * 100, 2),
            "Percent Greater Than 1.000": round((count_gt_1000 / total_matched) * 100, 2),
            "Percent Greater Than 1.500": round((count_gt_1500 / total_matched) * 100, 2),
            "10 largest_differences": sorted(self.response_times_, reverse=True)[:10],
            "capture_duration": str(duration),
            "start_time": str(start_time),
            "end_time": str(end_time)
        }

    def plot_raw_response_times(self):
        plt.figure(figsize=(14, 5))
        plt.plot(self.response_times_, color='mediumblue', linewidth=1)
        plt.title("Recorded SMPP Response Times", fontsize=14, fontweight='bold')
        plt.xlabel("Matched Submit_sm Packet Index", fontsize=12)
        plt.ylabel("Response Time (seconds)", fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.tight_layout()
        plt.savefig("raw_response_times.png", dpi=300)
        plt.close()

    def plot_response_distribution_by_count(self):

        stats_to_plot = {
            "Greater Than Mean": self.summary_["Percent Greater Than Mean Time Difference"],
            "Smaller Than Mean": self.summary_["Percent Smaller Than Mean Time Difference"],
            "< 0.001": self.summary_["Percent Less Than 0.001"],
            "< 0.002": self.summary_["Percent Less Than 0.002"],
            "< 0.003": self.summary_["Percent Less Than 0.003"],
            "< 0.004": self.summary_["Percent Less Than 0.004"],
            "< 0.005": self.summary_["Percent Less Than 0.005"],
            "< 0.010": self.summary_["Percent Less Than 0.010"],
            "< 0.020": self.summary_["Percent Less Than 0.020"],
            "< 0.030": self.summary_["Percent Less Than 0.030"],
            "< 0.040": self.summary_["Percent Less Than 0.040"],
            "< 0.050": self.summary_["Percent Less Than 0.050"],
            "< 0.070": self.summary_["Percent Less Than 0.070"],
            "< 0.090": self.summary_["Percent Less Than 0.090"],
            "> 1.000": self.summary_["Percent Greater Than 1.000"],
            "> 1.500": self.summary_["Percent Greater Than 1.500"]
        }

        df = pd.DataFrame(list(stats_to_plot.items()), columns=["Category", "Percent"])

        plt.figure(figsize=(12, 6))
        bars = plt.bar(df["Category"], df["Percent"], color='skyblue')
        plt.xticks(rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        mean_value = self.summary_["avg_response_time"]
        plt.title(f"Response Time Distribution ( Mean Response Time = {mean_value:.6f} sec)", fontsize=14, fontweight='bold')
        plt.xlabel("Time Categories", fontsize=12)
        plt.ylabel("Percent", fontsize=12)

        # Annotate bars
        for bar in bars:
            height = bar.get_height()
            plt.annotate(f'{height:,}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

        plt.tight_layout()
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # Save chart
        output_file = "response_time_distribution_by_percentage.png"
        plt.savefig(output_file, dpi=300)
        plt.close()

    def plot_response_distribution_by_percentage(self):

        stats_to_plot = {
            "Greater Than Mean": self.summary_["Count Greater Than Mean Time Difference"],
            "Smaller Than Mean": self.summary_["Count Smaller Than Mean Time Difference"],
            "< 0.001": self.summary_["Count Less Than 0.001"],
            "< 0.002": self.summary_["Count Less Than 0.002"],
            "< 0.003": self.summary_["Count Less Than 0.003"],
            "< 0.004": self.summary_["Count Less Than 0.004"],
            "< 0.005": self.summary_["Count Less Than 0.005"],
            "< 0.010": self.summary_["Count Less Than 0.010"],
            "< 0.020": self.summary_["Count Less Than 0.020"],
            "< 0.030": self.summary_["Count Less Than 0.030"],
            "< 0.040": self.summary_["Count Less Than 0.040"],
            "< 0.050": self.summary_["Count Less Than 0.050"],
            "< 0.070": self.summary_["Count Less Than 0.070"],
            "< 0.090": self.summary_["Count Less Than 0.090"],
            "> 1.000": self.summary_["Count Greater Than 1.000"],
            "> 1.500": self.summary_["Count Greater Than 1.500"]
        }

        df = pd.DataFrame(list(stats_to_plot.items()), columns=["Category", "Count"])

        plt.figure(figsize=(12, 6))
        bars = plt.bar(df["Category"], df["Count"], color='skyblue')
        plt.xticks(rotation=45, fontsize=10)
        plt.yticks(fontsize=10)
        mean_value = self.summary_["avg_response_time"]
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
        output_file = "response_time_distribution_by_count.png"
        plt.savefig(output_file, dpi=300)
        plt.close()

    def generate_summary_image(self, output_file: str = "summary_report.png", title: str = "PCAP Analysis Summary"):

        lines = []
        for k, v in self.summary_.items():
            if isinstance(v, dict):
                lines.append(f"{k}:")
                for subk, subv in v.items():
                    lines.append(f"    {subk}: {subv}")
            elif isinstance(v, list):
                lines.append(f"{k}: [{', '.join(str(i) for i in v)}]")
            else:
                lines.append(f"{k}: {v}")

        # Add padding for title
        lines.insert(0, "")  # Spacer after title

        # Create the image
        fig, ax = plt.subplots(figsize=(16, len(lines) * 0.3 + 1))
        ax.axis('off')

        # Draw title
        ax.text(0, 1.02, title, fontsize=24, fontweight='bold', ha='left', va='top')

        # Draw lines
        for i, line in enumerate(lines):
            ax.text(0, 1 - i * 0.04, line, fontsize=24, va='top', ha='left', family='monospace')

        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()

def main():
    file_path = "smpp_sample.pcap"
    analyzer = capture_analyzer(file_path, filter=None)

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
