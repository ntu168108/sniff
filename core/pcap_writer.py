"""
PCAP File Writer/Reader
- Standard libpcap format
- Batched writes for performance
- Thread-safe operations
"""

import struct
import threading
from pathlib import Path
from typing import Iterator, Optional
from dataclasses import dataclass

from .constants import (
    PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
    PCAP_LINKTYPE_ETHERNET, DEFAULT_SNAPLEN
)
from .decoder import PacketInfo


@dataclass
class PcapGlobalHeader:
    """PCAP file global header (24 bytes)"""
    magic: int = PCAP_MAGIC
    version_major: int = PCAP_VERSION_MAJOR
    version_minor: int = PCAP_VERSION_MINOR
    thiszone: int = 0           # GMT offset (always 0)
    sigfigs: int = 0            # Timestamp accuracy
    snaplen: int = DEFAULT_SNAPLEN
    linktype: int = PCAP_LINKTYPE_ETHERNET
    
    def to_bytes(self) -> bytes:
        return struct.pack(
            '<IHHIIII',
            self.magic,
            self.version_major,
            self.version_minor,
            self.thiszone,
            self.sigfigs,
            self.snaplen,
            self.linktype
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'PcapGlobalHeader':
        if len(data) < 24:
            raise ValueError("Invalid PCAP header: too short")
        
        magic = struct.unpack('<I', data[0:4])[0]
        
        # Check endianness
        if magic == 0xa1b2c3d4:
            fmt = '<'  # Little endian
        elif magic == 0xd4c3b2a1:
            fmt = '>'  # Big endian
        else:
            raise ValueError(f"Invalid PCAP magic: 0x{magic:08x}")
        
        values = struct.unpack(f'{fmt}IHHIIII', data[:24])
        return cls(
            magic=values[0],
            version_major=values[1],
            version_minor=values[2],
            thiszone=values[3],
            sigfigs=values[4],
            snaplen=values[5],
            linktype=values[6]
        )


@dataclass
class PcapPacketHeader:
    """PCAP packet header (16 bytes)"""
    ts_sec: int
    ts_usec: int
    caplen: int
    origlen: int
    
    def to_bytes(self) -> bytes:
        return struct.pack('<IIII', self.ts_sec, self.ts_usec, self.caplen, self.origlen)
    
    @classmethod
    def from_bytes(cls, data: bytes, big_endian: bool = False) -> 'PcapPacketHeader':
        fmt = '>IIII' if big_endian else '<IIII'
        values = struct.unpack(fmt, data[:16])
        return cls(
            ts_sec=values[0],
            ts_usec=values[1],
            caplen=values[2],
            origlen=values[3]
        )


class PcapWriter:
    """
    PCAP file writer with batched writes
    Thread-safe for multi-threaded capture
    """
    
    def __init__(self, filepath: str, snaplen: int = DEFAULT_SNAPLEN,
                 batch_size: int = 100, linktype: int = PCAP_LINKTYPE_ETHERNET):
        self.filepath = Path(filepath)
        self.snaplen = snaplen
        self.batch_size = batch_size
        self.linktype = linktype
        
        self._file = None
        self._buffer = bytearray()
        self._packet_count = 0
        self._byte_count = 0
        self._pending_packets = 0
        self._lock = threading.Lock()
        self._closed = False
    
    def open(self):
        """Open file and write global header"""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.filepath, 'wb')
        
        # Write global header
        header = PcapGlobalHeader(snaplen=self.snaplen, linktype=self.linktype)
        self._file.write(header.to_bytes())
        self._file.flush()
    
    def write_packet(self, ts_sec: int, ts_usec: int, data: bytes, origlen: int = None):
        """
        Write a packet to the buffer
        Flushes when batch_size is reached
        """
        if self._closed or self._file is None:
            return
        
        if origlen is None:
            origlen = len(data)
        
        # Truncate if needed
        caplen = min(len(data), self.snaplen)
        captured_data = data[:caplen]
        
        # Create packet header
        pkt_header = PcapPacketHeader(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            caplen=caplen,
            origlen=origlen
        )
        
        with self._lock:
            # Add to buffer
            self._buffer.extend(pkt_header.to_bytes())
            self._buffer.extend(captured_data)
            self._pending_packets += 1
            self._packet_count += 1
            self._byte_count += caplen
            
            # Flush if batch reached
            if self._pending_packets >= self.batch_size:
                self._flush_buffer()
    
    def write_packet_info(self, pkt_info: PacketInfo):
        """Write PacketInfo object"""
        origlen = pkt_info.origlen if pkt_info.origlen else len(pkt_info.data)
        self.write_packet(pkt_info.ts_sec, pkt_info.ts_usec, pkt_info.data, origlen)
    
    def _flush_buffer(self):
        """Flush buffer to disk (must hold lock)"""
        if self._buffer and self._file:
            self._file.write(self._buffer)
            self._buffer.clear()
            self._pending_packets = 0
    
    def flush(self):
        """Force flush buffer to disk"""
        with self._lock:
            self._flush_buffer()
            if self._file:
                self._file.flush()
    
    def close(self):
        """Close file"""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._flush_buffer()
            if self._file:
                self._file.close()
                self._file = None
    
    @property
    def packet_count(self) -> int:
        return self._packet_count
    
    @property
    def byte_count(self) -> int:
        return self._byte_count
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class PcapReader:
    """
    PCAP file reader
    Iterates over packets in file
    """
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self._file = None
        self._header = None
        self._big_endian = False
        self._packet_stt = 0
    
    def open(self):
        """Open file and read global header"""
        self._file = open(self.filepath, 'rb')
        header_data = self._file.read(24)
        
        if len(header_data) < 24:
            raise ValueError("Invalid PCAP file: too short")
        
        self._header = PcapGlobalHeader.from_bytes(header_data)
        
        # Check endianness
        magic = struct.unpack('<I', header_data[0:4])[0]
        self._big_endian = (magic == 0xd4c3b2a1)
    
    @property
    def header(self) -> Optional[PcapGlobalHeader]:
        return self._header
    
    def read_packet(self) -> Optional[PacketInfo]:
        """Read next packet, return None at EOF"""
        if self._file is None:
            return None
        
        # Read packet header
        pkt_header_data = self._file.read(16)
        if len(pkt_header_data) < 16:
            return None
        
        pkt_header = PcapPacketHeader.from_bytes(pkt_header_data, self._big_endian)
        
        # Read packet data
        data = self._file.read(pkt_header.caplen)
        if len(data) < pkt_header.caplen:
            return None
        
        self._packet_stt += 1
        
        return PacketInfo(
            stt=self._packet_stt,
            ts_sec=pkt_header.ts_sec,
            ts_usec=pkt_header.ts_usec,
            caplen=pkt_header.caplen,
            origlen=pkt_header.origlen,
            data=data
        )
    
    def __iter__(self) -> Iterator[PacketInfo]:
        """Iterate over all packets"""
        while True:
            pkt = self.read_packet()
            if pkt is None:
                break
            yield pkt
    
    def close(self):
        """Close file"""
        if self._file:
            self._file.close()
            self._file = None
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def count_packets(filepath: str) -> int:
    """Count packets in PCAP file"""
    count = 0
    with PcapReader(filepath) as reader:
        for _ in reader:
            count += 1
    return count


def get_pcap_info(filepath: str) -> dict:
    """Get PCAP file info"""
    path = Path(filepath)
    if not path.exists():
        return {"error": "File not found"}
    
    with PcapReader(filepath) as reader:
        first_ts = None
        last_ts = None
        count = 0
        total_bytes = 0
        
        for pkt in reader:
            ts = pkt.ts_sec + pkt.ts_usec / 1e6
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            count += 1
            total_bytes += pkt.caplen
    
    return {
        "filepath": str(path),
        "size_bytes": path.stat().st_size,
        "packet_count": count,
        "total_bytes": total_bytes,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "duration": (last_ts - first_ts) if first_ts and last_ts else 0,
        "snaplen": reader.header.snaplen if reader.header else 0,
    }

