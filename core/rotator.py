"""
Hourly File Rotator
- Auto rotate PCAP files at hour boundaries (HH:00:00)
- Format: {interface}_{YYYY-MM-DD}_{HH}.pcap
- Auto cleanup old files based on retention_days
- Callback on rotation for triggering analysis
"""

import os
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional, List

from .pcap_writer import PcapWriter
from .decoder import PacketInfo
from .constants import DEFAULT_SNAPLEN, DEFAULT_RETENTION_DAYS

logger = logging.getLogger(__name__)


class HourlyRotator:
    """
    Manages PCAP file rotation by hour
    Creates new file at each hour boundary
    """
    
    def __init__(
        self,
        base_dir: str,
        interface: str,
        snaplen: int = DEFAULT_SNAPLEN,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        on_rotate: Optional[Callable[[str, str, str], None]] = None,
        batch_size: int = 100
    ):
        """
        Args:
            base_dir: Base directory for PCAP files
            interface: Network interface name (used in filename)
            snaplen: Max packet capture length
            retention_days: Days to keep old files (0 = keep forever)
            on_rotate: Callback(old_file, interface, time_window) when rotation occurs
            batch_size: Packets per batch write
        """
        self.base_dir = Path(base_dir)
        self.interface = interface
        self.snaplen = snaplen
        self.retention_days = retention_days
        self.on_rotate = on_rotate
        self.batch_size = batch_size
        
        self._current_writer: Optional[PcapWriter] = None
        self._current_filepath: Optional[Path] = None
        self._current_hour: Optional[datetime] = None
        self._next_rotate_time: Optional[datetime] = None
        
        self._lock = threading.Lock()
        self._packet_count = 0
        self._byte_count = 0
        self._file_count = 0
        self._closed = False
    
    def _get_hour_start(self, dt: datetime) -> datetime:
        """Get start of hour (HH:00:00)"""
        return dt.replace(minute=0, second=0, microsecond=0)
    
    def _get_next_hour(self, dt: datetime) -> datetime:
        """Get start of next hour"""
        return self._get_hour_start(dt) + timedelta(hours=1)
    
    def _get_filepath(self, dt: datetime) -> Path:
        """
        Generate filepath for given datetime
        Format: base_dir/YYYY-MM-DD/{interface}_{YYYY-MM-DD}_{HH}.pcap
        """
        date_str = dt.strftime('%Y-%m-%d')
        hour_str = dt.strftime('%H')
        filename = f"{self.interface}_{date_str}_{hour_str}.pcap"
        
        date_dir = self.base_dir / date_str
        return date_dir / filename
    
    def _get_time_window(self, dt: datetime) -> str:
        """Get time window string: YYYY-MM-DD_HH"""
        return dt.strftime('%Y-%m-%d_%H')
    
    def _open_new_file(self, dt: datetime):
        """Open new PCAP file for given hour"""
        self._current_hour = self._get_hour_start(dt)
        self._next_rotate_time = self._get_next_hour(dt)
        self._current_filepath = self._get_filepath(dt)
        
        # Create directory if needed
        self._current_filepath.parent.mkdir(parents=True, exist_ok=True)
        
        # Open new writer
        self._current_writer = PcapWriter(
            str(self._current_filepath),
            snaplen=self.snaplen,
            batch_size=self.batch_size
        )
        self._current_writer.open()
        self._file_count += 1
        
        logger.info(f"Opened new PCAP: {self._current_filepath}")
    
    def _close_current_file(self) -> Optional[str]:
        """Close current file, return filepath if closed"""
        if self._current_writer:
            self._current_writer.close()
            old_path = str(self._current_filepath)
            self._current_writer = None
            self._current_filepath = None
            return old_path
        return None
    
    def _do_rotate(self, now: datetime):
        """Perform rotation: close old, open new, trigger callback, cleanup"""
        old_hour = self._current_hour
        old_path = self._close_current_file()
        
        # Open new file
        self._open_new_file(now)
        
        # Trigger callback
        if old_path and self.on_rotate and old_hour:
            try:
                time_window = self._get_time_window(old_hour)
                self.on_rotate(old_path, self.interface, time_window)
            except Exception as e:
                logger.error(f"Rotation callback error: {e}")
        
        # Cleanup old files
        if self.retention_days > 0:
            self._cleanup_old_files()
    
    def _cleanup_old_files(self):
        """Remove files older than retention_days"""
        if self.retention_days <= 0:
            return
        
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        cutoff_date_str = cutoff.strftime('%Y-%m-%d')
        
        try:
            for date_dir in self.base_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                
                # Parse directory date
                try:
                    dir_date_str = date_dir.name
                    if dir_date_str < cutoff_date_str:
                        # Remove entire directory
                        for f in date_dir.iterdir():
                            f.unlink()
                        date_dir.rmdir()
                        logger.info(f"Cleaned up old directory: {date_dir}")
                except (ValueError, OSError) as e:
                    logger.warning(f"Cleanup error for {date_dir}: {e}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes, origlen: int = None):
        """
        Write packet, rotating file if hour boundary crossed
        """
        if self._closed:
            return
        
        with self._lock:
            now = datetime.now()
            
            # Check if need to rotate
            if self._current_writer is None:
                self._open_new_file(now)
            elif now >= self._next_rotate_time:
                self._do_rotate(now)
            
            # Write packet
            if self._current_writer:
                self._current_writer.write_packet(ts_sec, ts_usec, data, origlen)
                self._packet_count += 1
                self._byte_count += len(data)
    
    def write_packet_info(self, pkt_info: PacketInfo):
        """Write PacketInfo object"""
        origlen = pkt_info.origlen if pkt_info.origlen else len(pkt_info.data)
        self.write_packet(pkt_info.ts_sec, pkt_info.ts_usec, pkt_info.data, origlen)
    
    def flush(self):
        """Force flush current file"""
        with self._lock:
            if self._current_writer:
                self._current_writer.flush()
    
    def force_rotate(self):
        """Force rotation now (for graceful shutdown)"""
        with self._lock:
            if self._current_writer:
                self._do_rotate(datetime.now())
    
    def close(self):
        """Close current file"""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            
            old_hour = self._current_hour
            old_path = self._close_current_file()
            
            # Trigger final callback
            if old_path and self.on_rotate and old_hour:
                try:
                    time_window = self._get_time_window(old_hour)
                    self.on_rotate(old_path, self.interface, time_window)
                except Exception as e:
                    logger.error(f"Final rotation callback error: {e}")
    
    @property
    def current_filepath(self) -> Optional[str]:
        """Get current PCAP file path"""
        return str(self._current_filepath) if self._current_filepath else None
    
    @property
    def current_hour(self) -> Optional[datetime]:
        return self._current_hour
    
    @property
    def next_rotate_time(self) -> Optional[datetime]:
        return self._next_rotate_time
    
    @property
    def packet_count(self) -> int:
        return self._packet_count
    
    @property
    def byte_count(self) -> int:
        return self._byte_count
    
    @property
    def file_count(self) -> int:
        return self._file_count
    
    def get_status(self) -> dict:
        """Get rotator status"""
        return {
            "current_file": self.current_filepath,
            "current_hour": self._current_hour.isoformat() if self._current_hour else None,
            "next_rotate": self._next_rotate_time.isoformat() if self._next_rotate_time else None,
            "packet_count": self._packet_count,
            "byte_count": self._byte_count,
            "file_count": self._file_count,
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def list_pcap_files(base_dir: str, interface: str = None, 
                    date: str = None) -> List[dict]:
    """
    List PCAP files in base directory
    
    Args:
        base_dir: Base directory to search
        interface: Filter by interface name (optional)
        date: Filter by date YYYY-MM-DD (optional)
    
    Returns:
        List of file info dicts
    """
    base_path = Path(base_dir)
    if not base_path.exists():
        return []
    
    results = []
    
    for date_dir in sorted(base_path.iterdir()):
        if not date_dir.is_dir():
            continue
        
        # Filter by date
        if date and date_dir.name != date:
            continue
        
        for pcap_file in sorted(date_dir.glob('*.pcap')):
            # Parse filename: {interface}_{date}_{hour}.pcap
            parts = pcap_file.stem.split('_')
            if len(parts) >= 3:
                file_interface = '_'.join(parts[:-2])
                file_date = parts[-2]
                file_hour = parts[-1]
                
                # Filter by interface
                if interface and file_interface != interface:
                    continue
                
                results.append({
                    "filepath": str(pcap_file),
                    "interface": file_interface,
                    "date": file_date,
                    "hour": file_hour,
                    "size_bytes": pcap_file.stat().st_size,
                    "mtime": datetime.fromtimestamp(pcap_file.stat().st_mtime).isoformat(),
                })
    
    return results


def get_available_dates(base_dir: str) -> List[str]:
    """Get list of available dates in base directory"""
    base_path = Path(base_dir)
    if not base_path.exists():
        return []
    
    dates = []
    for date_dir in sorted(base_path.iterdir()):
        if date_dir.is_dir():
            try:
                # Validate date format
                datetime.strptime(date_dir.name, '%Y-%m-%d')
                dates.append(date_dir.name)
            except ValueError:
                pass
    
    return dates

