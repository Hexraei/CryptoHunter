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
        (CS_ARCH_RISCV, CS_MODE_RISCV64, "RISCV64", 64, "LE"),
        (CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN, "PowerPC", 32, "BE"),
    ]
    
    SAMPLE_SIZE = 4000  # Bytes to analyze per offset
    
    # Extended offsets for raw binaries without headers (like stripped sections)
    RAW_BINARY_OFFSETS = [
        0x00, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800,
        0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000
    ]
    
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
        
        # Check if binary has standard header (ELF/PE) - if not, use extended offsets
        has_header = (data[:4] == b'\x7fELF' or data[:2] == b'MZ')
        
        if offsets is None:
            offsets = self.DEFAULT_OFFSETS if has_header else self.RAW_BINARY_OFFSETS
        
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
        
        # If best result has low coverage, try string-based detection as fallback
        if (not results or results[0].details.get("coverage", 0) < 0.3):
            string_result = self._detect_from_strings(data)
            if string_result:
                # Insert at beginning if string detection is confident
                if not results or string_result.confidence > results[0].confidence:
                    results.insert(0, string_result)
                else:
                    results.append(string_result)
        
        return results
    
    def _detect_from_strings(self, data: bytes) -> ArchDetectionResult:
        """
        Detect architecture from embedded strings in binary.
        Useful for binaries that don't disassemble well (e.g., extracted sections).
        """
        # Architecture patterns to search for
        arch_patterns = {
            'RISCV64': [b'riscv64', b'rv64', b'RISCV64'],
            'RISCV32': [b'riscv32', b'rv32', b'RISCV32'],
            'ARM64': [b'aarch64', b'arm64', b'armv8'],
            'ARM32': [b'arm-linux', b'armv7', b'armhf', b'armel'],
            'MIPS-BE': [b'mips-linux', b'mips32', b'mipsbe'],
            'MIPS-LE': [b'mipsel', b'mips64el'],
            'x86-64': [b'x86_64', b'x86-64', b'amd64'],
            'x86': [b'i386', b'i686', b'x86-linux'],
            'PowerPC': [b'powerpc', b'ppc64', b'ppc-'],
        }
        
        data_lower = data.lower()
        
        # Count occurrences for each architecture
        arch_counts = {}
        for arch, patterns in arch_patterns.items():
            count = 0
            for p in patterns:
                count += data_lower.count(p.lower())
            if count > 0:
                arch_counts[arch] = count
        
        if not arch_counts:
            return None
        
        # Get best match
        best_arch = max(arch_counts, key=arch_counts.get)
        count = arch_counts[best_arch]
        
        # Confidence based on count (more occurrences = higher confidence)
        if count >= 20:
            confidence = 0.90
        elif count >= 10:
            confidence = 0.80
        elif count >= 5:
            confidence = 0.70
        else:
            confidence = 0.60
        
        # Determine bits and endian
        bits = 64 if '64' in best_arch else 32
        if best_arch in ['RISCV32', 'RISCV64']:
            endian = 'LE'  # RISC-V is always little-endian
        elif 'BE' in best_arch:
            endian = 'BE'
        else:
            endian = 'LE'
        
        return ArchDetectionResult(
            architecture=best_arch,
            confidence=confidence,
            offset=0,
            bits=bits,
            endian=endian,
            method="string_search",
            details={
                "string_matches": count,
                "all_matches": arch_counts,
                "note": "Detected from embedded strings (binary may not start with code)"
            }
        )


# Convenience function
def detect_with_capstone(data: bytes) -> ArchDetectionResult:
    """Quick detection using Capstone."""
    detector = CapstoneDetector()
    return detector.get_best(data)

