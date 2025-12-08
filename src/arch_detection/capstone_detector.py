"""
Capstone-based architecture detector.
Uses strict disassembly with coverage and continuity metrics.
This is the current best method for architecture detection.
"""
from typing import List
from .base import BaseDetector, ArchDetectionResult

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class CapstoneDetector(BaseDetector):
    """
    Architecture detection using Capstone disassembler.
    
    Method: Disassemble at multiple offsets, measure coverage (bytes decoded / total)
    and continuity (no gaps between instructions). Higher scores = better match.
    """
    
    name = "capstone"
    weight = 1.5  # Reliable but can be fooled by structured data
    
    # Architectures to test with Capstone
    ARCH_CONFIGS = [
        (CS_ARCH_ARM, CS_MODE_ARM, "ARM32", 32, "LE"),
        (CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN, "ARM32", 32, "BE"),
        (CS_ARCH_ARM, CS_MODE_THUMB, "ARM-Thumb", 32, "LE"),
        (CS_ARCH_ARM64, CS_MODE_ARM, "ARM64", 64, "LE"),
        (CS_ARCH_X86, CS_MODE_32, "x86", 32, "LE"),
        (CS_ARCH_X86, CS_MODE_64, "x86-64", 64, "LE"),
        (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN, "MIPS-BE", 32, "BE"),
        (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN, "MIPS-LE", 32, "LE"),
        (CS_ARCH_RISCV, CS_MODE_RISCV32, "RISCV32", 32, "LE"),
        (CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN, "PowerPC", 32, "BE"),
    ]
    
    SAMPLE_SIZE = 4000  # Bytes to analyze per offset
    
    def is_available(self) -> bool:
        return CAPSTONE_AVAILABLE
    
    def _score_disassembly(self, data: bytes, arch: int, mode: int, offset: int) -> dict:
        """
        Score how well data disassembles with given architecture.
        
        Returns dict with:
            - coverage: fraction of bytes that were decoded as instructions
            - continuity: fraction of instructions without gaps
            - instruction_count: number of valid instructions
        """
        if offset >= len(data):
            return {"coverage": 0, "continuity": 0, "instruction_count": 0}
        
        sample = data[offset:offset + self.SAMPLE_SIZE]
        if len(sample) < 100:
            return {"coverage": 0, "continuity": 0, "instruction_count": 0}
        
        try:
            md = Cs(arch, mode)
            instructions = list(md.disasm(sample, offset))
            
            if not instructions:
                return {"coverage": 0, "continuity": 0, "instruction_count": 0}
            
            # Metric 1: Coverage (bytes decoded / sample size)
            total_bytes = sum(i.size for i in instructions)
            coverage = total_bytes / len(sample)
            
            # Metric 2: Continuity (no gaps between instructions)
            gaps = 0
            for i in range(len(instructions) - 1):
                expected_next = instructions[i].address + instructions[i].size
                if instructions[i + 1].address != expected_next:
                    gaps += 1
            
            continuity = 1 - (gaps / len(instructions)) if len(instructions) > 1 else 1.0
            
            return {
                "coverage": coverage,
                "continuity": continuity,
                "instruction_count": len(instructions)
            }
            
        except Exception:
            return {"coverage": 0, "continuity": 0, "instruction_count": 0}
    
    def detect(self, data: bytes, offsets: List[int] = None) -> List[ArchDetectionResult]:
        """Run detection across all architectures and offsets."""
        if not CAPSTONE_AVAILABLE:
            return []
        
        if offsets is None:
            offsets = self.DEFAULT_OFFSETS
        
        results = []
        
        for arch, mode, arch_name, bits, endian in self.ARCH_CONFIGS:
            best_score = 0
            best_offset = 0
            best_metrics = {}
            
            for offset in offsets:
                metrics = self._score_disassembly(data, arch, mode, offset)
                
                # Combined score: coverage (40%) + continuity (60%)
                score = metrics["coverage"] * 40 + metrics["continuity"] * 60
                
                if score > best_score:
                    best_score = score
                    best_offset = offset
                    best_metrics = metrics
            
            if best_score > 30:  # Minimum threshold
                confidence = min(best_score / 100, 1.0)
                results.append(ArchDetectionResult(
                    architecture=arch_name,
                    confidence=confidence,
                    offset=best_offset,
                    bits=bits,
                    endian=endian,
                    method=self.name,
                    details={
                        "score": best_score,
                        "coverage": best_metrics.get("coverage", 0),
                        "continuity": best_metrics.get("continuity", 0),
                        "instructions": best_metrics.get("instruction_count", 0)
                    }
                ))
        
        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results


# Convenience function
def detect_with_capstone(data: bytes) -> ArchDetectionResult:
    """Quick detection using Capstone."""
    detector = CapstoneDetector()
    return detector.get_best(data)
