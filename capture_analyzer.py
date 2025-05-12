import pyshark
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from rich.progress import Progress
from statistics import mean
import matplotlib.pyplot as plt
import pandas as pd
from logger import logger

__version__ = "1.0.0"

class capture_analyzer:

    def __init__(self, file_path, filter=None):
        self.file_path_ = file_path
        self.logger_ = logger(log_level='DEBUG')
        self.logger_.debug(f"Loading PCAP file: {file_path}")
        self.pcap_ = pyshark.FileCapture(file_path, display_filter=filter, keep_packets=False)

        pcap_name = Path(file_path).stem
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.output_dir_ = Path("output") / f"{pcap_name}_{timestamp}"
        # self.output_dir_.mkdir(parents=True, exist_ok=True)
        
        self.sessions_ = defaultdict(set)
        self.request_ = {}
        self.request_resp_ = {}
        self.summary_ = {}
        self.response_times_ = []
        self.logger_.debug("PCAP file loaded successfully.")

    def close(self):
        self.logger_.debug("Closing PCAP capture.")
        self.pcap_.close()

    def analyze_pcab(self, packet_type):
        self.logger_.debug(f"Starting PCAP analysis for packet_type = {packet_type}")
        protocol_counter = Counter()
        timestamps = []
        packet_count = sum(1 for _ in self.pcap_)

        with Progress() as progress:
            task = progress.add_task("[green]Processing packets ...", total=packet_count)

            for pkt in self.pcap_:
                try:
                    protocol = pkt.highest_layer
                    protocol_counter[protocol] += 1
                    if protocol != 'SMPP':
                        progress.update(task, advance=1)
                        continue
                    timestamp = float(pkt.sniff_timestamp)
                    timestamps.append(timestamp)
                    cmd_type = pkt.smpp.command_id.showname_value.lower()
                    seq_num = pkt.smpp.sequence_number

                    if 'bind_' in cmd_type and 'resp' not in cmd_type:
                        src_ip = pkt.ip.src
                        src_port = pkt.tcp.srcport
                        system_id = pkt.smpp.system_id
                        target_addr = f"{src_ip}:{src_port}"
                        self.sessions_[system_id].add(target_addr)

                    if packet_type in cmd_type and 'resp' not in cmd_type:
                        self.request_[seq_num] = timestamp

                    elif f'{packet_type} - resp' in cmd_type:
                        self.request_resp_[seq_num] = timestamp

                except AttributeError as e:
                    self.logger_.error(f"PCAP analysis failed: {e}")
                    self.pcap_.close()
                    exit()

                progress.update(task, advance=1)

        if len(self.request_) == 0:
            self.logger_.error(f"No results found for specified packet_type = {packet_type}.")
            exit()

        self.logger_.debug(f"Packet processing complete. Total packets: {packet_count}")
        self.logger_.debug(f"Matching requests to responses...")

        start_time = datetime.fromtimestamp(min(timestamps))
        end_time = datetime.fromtimestamp(max(timestamps))
        duration = end_time - start_time
        negative_response_time = []

        # Match requests with responses
        self.response_times_ = []
        self.response_time_map_ = {}
        for seq in self.request_:
            if seq in self.request_resp_:
                if self.request_resp_[seq] < self.request_[seq]:
                    negative_response_time.append(seq)
                    self.logger_.error(f"Response time is negative for seq {seq} ")
                    continue
                delta = self.request_resp_[seq] - self.request_[seq]
                self.response_times.append(delta)
                self.response_time_map_[seq] = delta

        unmatched = set(self.request_) - set(self.request_resp_)

        self.logger_.debug(f"Matched {len(self.response_times_)} request/response pairs.")
        self.logger_.debug(f"Unmatched sequences: {len(unmatched)}")

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
            "Total Packets": packet_count,
            "Protocols": dict(protocol_counter),
            "Connections": len(self.sessions_),
            "Sessions": {k: len(v) for k, v in self.sessions_.items()},
            "Packet Type": packet_type,
            f"'{packet_type}' Count": len(self.request_),
            f"'{packet_type} - resp' Count": len(self.request_resp_),
            f"Unmatched '{packet_type}' sequences": list(unmatched),
            f"Negative Response '{packet_type}' sequences": list(negative_response_time),
            "Matched Request": len(self.response_times_),
            "Min Response Time": min_diff,
            "Max Response Time": max_diff,
            "Avg Response Time": mean_diff,
            "Count Greater Than Mean Time Difference": count_gt_mean,
            "Percent Greater Than Mean Time Difference": round((count_gt_mean / total_matched) * 100, 2),
            "Count Smaller Than Mean Time Difference": count_lt_mean,
            "Percent Smaller Than Mean Time Difference": round((count_lt_mean / total_matched) * 100, 2),
            "Count Less Than 0.001": count_001,
            "Percent Less Than 0.001": round((count_001 / total_matched) * 100, 2),
            "Count Less Than 0.002": count_002,
            "Percent Less Than 0.002": round((count_002 / total_matched) * 100, 2),
            "Count Less Than 0.003": count_003,
            "Percent Less Than 0.003": round((count_003 / total_matched) * 100, 2),
            "Count Less Than 0.004": count_004,
            "Percent Less Than 0.004": round((count_004 / total_matched) * 100, 2),
            "Count Less Than 0.005": count_005,
            "Percent Less Than 0.005": round((count_005 / total_matched) * 100, 2),
            "Count Less Than 0.010": count_010,
            "Percent Less Than 0.010": round((count_010 / total_matched) * 100, 2),
            "Count Less Than 0.020": count_020,
            "Percent Less Than 0.020": round((count_020 / total_matched) * 100, 2),
            "Count Less Than 0.030": count_030,
            "Percent Less Than 0.030": round((count_030 / total_matched) * 100, 2),
            "Count Less Than 0.040": count_040,
            "Percent Less Than 0.040": round((count_040 / total_matched) * 100, 2),
            "Count Less Than 0.050": count_050,
            "Percent Less Than 0.050": round((count_050 / total_matched) * 100, 2),
            "Count Less Than 0.070": count_070,
            "Percent Less Than 0.070": round((count_070 / total_matched) * 100, 2),
            "Count Less Than 0.090": count_090,
            "Percent Less Than 0.090": round((count_090 / total_matched) * 100, 2),
            "Count Greater Than 1.000": count_gt_1000,
            "Percent Greater Than 1.000": round((count_gt_1000 / total_matched) * 100, 2),
            "Count Greater Than 1.500": count_gt_1500,
            "Percent Greater Than 1.500": round((count_gt_1500 / total_matched) * 100, 2),
            "10 Largest Differences": ["{:.2f}".format(x) for x in sorted(self.response_times_, reverse=True)[:10]],
            "Capture Duration": str(duration),
            "Start Time": str(start_time),
            "End time": str(end_time)
        }

        self.output_dir_ = Path(self.output_dir_) / f"{packet_type}"
        self.output_dir_.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(list(self.response_time_map_.items()), columns=["Sequence Number", "Response Time (s)"])
        df.to_excel(f"{self.output_dir_}/response_times.xlsx", index=False)
        self.logger_.debug("Summary generation completed.")

    def plot_raw_response_times(self):
        self.logger_.debug("Plotting raw response times.")
        plt.figure(figsize=(14, 5))
        plt.plot(self.response_times_, color='mediumblue', linewidth=1)
        plt.title("Recorded SMPP Response Times", fontsize=14, fontweight='bold')
        plt.xlabel("Matched Submit_sm Packet Index", fontsize=12)
        plt.ylabel("Response Time (seconds)", fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.6)
        plt.tight_layout()
        output_file = self.output_dir_ / "summary_report.png"
        plt.savefig(output_file, dpi=300)
        plt.close()
        self.logger_.debug(f"Raw response times saved to {output_file}")

    def plot_response_distribution_by_count(self):
        self.logger_.debug("Generating response distribution by percentage.")
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
        mean_value = self.summary_.get("avg_response_time", None)

        if mean_value is not None:
            title = f"Response Time Distribution (Mean Response Time = {mean_value:.6f} sec)"
        else:
            title = "Response Time Distribution (Mean Response Time = N/A)"

        plt.title(title, fontsize=14, fontweight='bold')
        plt.xlabel("Time Categories", fontsize=12)
        plt.ylabel("Percent", fontsize=12)

        # Annotate bars
        for bar in bars:
            height = bar.get_height()
            plt.annotate(f'{height}%', xy=(bar.get_x() + bar.get_width() / 2, height),
                         xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

        plt.tight_layout()
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # Save chart
        output_file = self.output_dir_ / "response_time_distribution_by_percentage.png"
        plt.savefig(output_file, dpi=300)
        plt.close()
        self.logger_.debug(f"Distribution plot (percentage) saved to {output_file}")

    def plot_response_distribution_by_percentage(self):
        self.logger_.debug("Generating response distribution by count.")
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
        mean_value = self.summary_.get("avg_response_time", None)

        if mean_value is not None:
            title = f"Response Time Distribution ( Mean Response Time = {mean_value:.6f} sec)"
        else:
            title = "Response Time Distribution (Mean Response Time = N/A)"
        plt.title(title, fontsize=14, fontweight='bold')
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
        output_file = self.output_dir_ / "response_time_distribution_by_count.png"
        plt.savefig(output_file, dpi=300)
        plt.close()
        self.logger_.debug(f"Distribution plot (count) saved to {output_file}")

    def generate_summary_image(self, title: str = "PCAP Analysis Summary"):
        output_file = self.output_dir_ / "summary.png"
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
        self.logger_.debug(f"Summary image saved to {output_file}")
