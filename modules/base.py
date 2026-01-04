"""
Base Module - Abstract base class for analysis modules
- Defines interface for analysis plugins
- Provides common utilities
- Output format specifications
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class Detection:
    """Single detection/finding from analysis"""
    stt: int                    # Packet sequence number
    ts_sec: int                 # Timestamp seconds
    label: str                  # Detection label (e.g., "port-scan", "syn-flood")
    src: str = ""               # Source address
    dst: str = ""               # Destination address
    sport: int = 0              # Source port
    dport: int = 0              # Destination port
    proto: str = ""             # Protocol
    details: Dict[str, Any] = field(default_factory=dict)  # Extra details
    
    def to_dict(self) -> dict:
        return {
            "stt": self.stt,
            "ts_sec": self.ts_sec,
            "label": self.label,
            "src": self.src,
            "dst": self.dst,
            "sport": self.sport,
            "dport": self.dport,
            "proto": self.proto,
            **self.details
        }
    
    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class Summary:
    """Analysis summary for a time window"""
    module_name: str
    interface: str
    time_window: str            # Format: YYYY-MM-DD_HH
    pcap_file: str
    
    # Stats
    total_packets: int = 0
    analyzed_packets: int = 0
    total_hits: int = 0
    
    # Labels breakdown
    labels: Dict[str, int] = field(default_factory=dict)
    
    # Top sources/destinations
    top_sources: List[tuple] = field(default_factory=list)  # [(ip, count), ...]
    top_destinations: List[tuple] = field(default_factory=list)
    
    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    duration_sec: float = 0.0
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "module_name": self.module_name,
            "interface": self.interface,
            "time_window": self.time_window,
            "pcap_file": self.pcap_file,
            "total_packets": self.total_packets,
            "analyzed_packets": self.analyzed_packets,
            "total_hits": self.total_hits,
            "labels": self.labels,
            "top_sources": self.top_sources,
            "top_destinations": self.top_destinations,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.duration_sec,
            "errors": self.errors,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class BaseModule(ABC):
    """
    Abstract base class for analysis modules
    
    Subclass this to create new analysis modules.
    Implement the `name` property and `analyze()` method.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Module name (used in output directory)
        Should be lowercase, alphanumeric with underscores
        """
        pass
    
    @property
    def description(self) -> str:
        """Module description"""
        return "No description"
    
    @property
    def version(self) -> str:
        """Module version"""
        return "1.0.0"
    
    @abstractmethod
    def analyze(
        self,
        pcap_path: str,
        output_dir: str,
        interface: str,
        time_window: str,
    ) -> Summary:
        """
        Analyze a PCAP file and write results
        
        Args:
            pcap_path: Path to PCAP file
            output_dir: Directory to write output files
            interface: Network interface name
            time_window: Time window string (YYYY-MM-DD_HH)
        
        Returns:
            Summary object with analysis results
        """
        pass
    
    def get_output_dir(self, base_dir: str, time_window: str) -> Path:
        """
        Get output directory for this module
        Creates: base_dir/module_name/YYYY-MM-DD/
        """
        # Parse date from time_window (YYYY-MM-DD_HH)
        date_str = time_window.split('_')[0] if '_' in time_window else time_window
        
        output_dir = Path(base_dir) / self.name / date_str
        output_dir.mkdir(parents=True, exist_ok=True)
        
        return output_dir
    
    def get_output_basename(self, interface: str, time_window: str) -> str:
        """
        Get base filename for output files
        Format: {interface}_{time_window}
        """
        return f"{interface}_{time_window}"
    
    def write_summary(self, output_dir: Path, basename: str, summary: Summary):
        """Write summary JSON file"""
        summary_path = output_dir / f"{basename}.summary.json"
        
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary.to_json())
            logger.info(f"Wrote summary: {summary_path}")
        except Exception as e:
            logger.error(f"Error writing summary: {e}")
    
    def write_detections(self, output_dir: Path, basename: str, detections: List[Detection]):
        """Write detections JSONL file (one JSON per line)"""
        if not detections:
            return
        
        index_path = output_dir / f"{basename}.index.jsonl"
        
        try:
            with open(index_path, 'w', encoding='utf-8') as f:
                for det in detections:
                    f.write(det.to_json_line() + '\n')
            logger.info(f"Wrote {len(detections)} detections: {index_path}")
        except Exception as e:
            logger.error(f"Error writing detections: {e}")
    
    def write_output(
        self,
        output_dir: str,
        interface: str,
        time_window: str,
        summary: Summary,
        detections: List[Detection] = None,
    ):
        """
        Write all output files for this analysis
        
        Creates:
        - {basename}.summary.json - Analysis summary
        - {basename}.index.jsonl - Detections (if any)
        """
        out_dir = self.get_output_dir(output_dir, time_window)
        basename = self.get_output_basename(interface, time_window)
        
        self.write_summary(out_dir, basename, summary)
        
        if detections:
            self.write_detections(out_dir, basename, detections)
    
    def __repr__(self):
        return f"<{self.__class__.__name__} name={self.name} version={self.version}>"


def read_summary(filepath: str) -> Optional[Summary]:
    """Read summary from JSON file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return Summary(
            module_name=data.get('module_name', ''),
            interface=data.get('interface', ''),
            time_window=data.get('time_window', ''),
            pcap_file=data.get('pcap_file', ''),
            total_packets=data.get('total_packets', 0),
            analyzed_packets=data.get('analyzed_packets', 0),
            total_hits=data.get('total_hits', 0),
            labels=data.get('labels', {}),
            top_sources=data.get('top_sources', []),
            top_destinations=data.get('top_destinations', []),
            start_time=data.get('start_time', 0.0),
            end_time=data.get('end_time', 0.0),
            duration_sec=data.get('duration_sec', 0.0),
            errors=data.get('errors', []),
        )
    except Exception as e:
        logger.error(f"Error reading summary {filepath}: {e}")
        return None


def read_detections(filepath: str) -> List[Detection]:
    """Read detections from JSONL file"""
    detections = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    det = Detection(
                        stt=data.get('stt', 0),
                        ts_sec=data.get('ts_sec', 0),
                        label=data.get('label', ''),
                        src=data.get('src', ''),
                        dst=data.get('dst', ''),
                        sport=data.get('sport', 0),
                        dport=data.get('dport', 0),
                        proto=data.get('proto', ''),
                        details={k: v for k, v in data.items() 
                                if k not in ('stt', 'ts_sec', 'label', 'src', 'dst', 'sport', 'dport', 'proto')}
                    )
                    detections.append(det)
                except json.JSONDecodeError:
                    continue
    
    except Exception as e:
        logger.error(f"Error reading detections {filepath}: {e}")
    
    return detections

