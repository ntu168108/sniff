"""
Dummy Analysis Module - Example module for testing
- Counts packets by protocol
- Detects simple patterns (port scans, high rate IPs)
- Demonstrates module structure
"""

import time
import logging
from collections import Counter
from typing import List

from ..base import BaseModule, Summary, Detection
from core.pcap_writer import PcapReader
from core.decoder import decode_packet

logger = logging.getLogger(__name__)


class DummyModule(BaseModule):
    """
    Example analysis module
    
    Features:
    - Protocol distribution
    - Top talkers (by packets)
    - Simple port scan detection (many ports from same source)
    """
    
    @property
    def name(self) -> str:
        return "dummy"
    
    @property
    def description(self) -> str:
        return "Example module - Protocol stats & simple anomaly detection"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def analyze(
        self,
        pcap_path: str,
        output_dir: str,
        interface: str,
        time_window: str,
    ) -> Summary:
        """Analyze PCAP file"""
        start_time = time.time()
        
        # Initialize counters
        proto_counts = Counter()
        src_counts = Counter()
        dst_counts = Counter()
        src_dst_port_pairs = {}  # {src_ip: set(dst_ports)}
        
        # Results
        detections: List[Detection] = []
        total_packets = 0
        analyzed_packets = 0
        errors = []
        
        try:
            with PcapReader(pcap_path) as reader:
                for pkt_info in reader:
                    total_packets += 1
                    
                    try:
                        decoded = decode_packet(pkt_info.data)
                        analyzed_packets += 1
                        
                        # Count protocol
                        proto = decoded.protocol_name or "UNKNOWN"
                        proto_counts[proto] += 1
                        
                        # Count sources/destinations
                        if decoded.src_addr:
                            src_counts[decoded.src_addr] += 1
                        if decoded.dst_addr:
                            dst_counts[decoded.dst_addr] += 1
                        
                        # Track port pairs for port scan detection
                        if decoded.src_addr and decoded.dst_port:
                            if decoded.src_addr not in src_dst_port_pairs:
                                src_dst_port_pairs[decoded.src_addr] = set()
                            src_dst_port_pairs[decoded.src_addr].add(decoded.dst_port)
                    
                    except Exception as e:
                        if len(errors) < 10:  # Limit error logging
                            errors.append(f"Packet {pkt_info.stt}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            errors.append(f"PCAP read error: {str(e)}")
        
        # Detect port scans (source hitting many ports)
        PORT_SCAN_THRESHOLD = 20
        for src_ip, ports in src_dst_port_pairs.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                det = Detection(
                    stt=0,
                    ts_sec=int(start_time),
                    label="port-scan",
                    src=src_ip,
                    dst="multiple",
                    dport=len(ports),
                    proto="TCP",
                    details={"unique_ports": len(ports)}
                )
                detections.append(det)
        
        # Detect high-rate sources (simple DoS indicator)
        HIGH_RATE_THRESHOLD = 1000  # packets
        for src_ip, count in src_counts.items():
            if count >= HIGH_RATE_THRESHOLD:
                det = Detection(
                    stt=0,
                    ts_sec=int(start_time),
                    label="high-rate-source",
                    src=src_ip,
                    details={"packet_count": count}
                )
                detections.append(det)
        
        end_time = time.time()
        
        # Build summary
        summary = Summary(
            module_name=self.name,
            interface=interface,
            time_window=time_window,
            pcap_file=pcap_path,
            total_packets=total_packets,
            analyzed_packets=analyzed_packets,
            total_hits=len(detections),
            labels={
                "port-scan": sum(1 for d in detections if d.label == "port-scan"),
                "high-rate-source": sum(1 for d in detections if d.label == "high-rate-source"),
            },
            top_sources=src_counts.most_common(10),
            top_destinations=dst_counts.most_common(10),
            start_time=start_time,
            end_time=end_time,
            duration_sec=end_time - start_time,
            errors=errors,
        )
        
        # Add protocol breakdown to summary
        summary.labels.update({f"proto_{k}": v for k, v in proto_counts.most_common(10)})
        
        # Write output
        self.write_output(
            output_dir=output_dir,
            interface=interface,
            time_window=time_window,
            summary=summary,
            detections=detections
        )
        
        return summary


# For auto-discovery
__all__ = ['DummyModule']

