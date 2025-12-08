"""
Base classes for architecture detection.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class ArchDetectionResult:
    """Result from an architecture detector."""
    architecture: str      # e.g., "ARM32", "x86", "MIPS-BE"
    confidence: float      # 0.0 - 1.0
    offset: int = 0        # Code start offset in binary
    bits: int = 32         # 16, 32, or 64
    endian: str = "LE"     # "LE" (little-endian) or "BE" (big-endian)
    method: str = ""       # Which detector produced this result
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "architecture": self.architecture,
            "confidence": self.confidence,
            "offset": self.offset,
            "bits": self.bits,
            "endian": self.endian,
            "method": self.method,
            "details": self.details
        }
    
    def __repr__(self):
        return f"ArchDetectionResult({self.architecture}, conf={self.confidence:.2f}, offset=0x{self.offset:X})"


class BaseDetector(ABC):
    """Base class for all architecture detectors."""
    
    name: str = "base"
    weight: float = 1.0  # Weight in ensemble voting (higher = more trusted)
    
    # Standard offsets to test (skip headers)
    DEFAULT_OFFSETS = [0, 0x100, 0x200, 0x400, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000]
    
    # Supported architectures
    ARCHITECTURES = [
        "ARM32", "ARM64", "ARM-Thumb",
        "x86", "x86-64",
        "MIPS-BE", "MIPS-LE",
        "RISCV32", "RISCV64",
        "PowerPC",
        "SPARC",
        "Unknown"
    ]
    
    @abstractmethod
    def detect(self, data: bytes, offsets: List[int] = None) -> List[ArchDetectionResult]:
        """
        Run detection on binary data.
        
        Args:
            data: Binary data to analyze
            offsets: List of offsets to test (defaults to DEFAULT_OFFSETS)
            
        Returns:
            List of detection results, sorted by confidence (highest first)
        """
        pass
    
    def get_best(self, data: bytes) -> Optional[ArchDetectionResult]:
        """Get single best result."""
        results = self.detect(data)
        return max(results, key=lambda x: x.confidence) if results else None
    
    def is_available(self) -> bool:
        """Check if this detector is available (dependencies installed)."""
        return True
