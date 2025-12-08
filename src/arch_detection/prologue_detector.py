"""
Function prologue pattern detector for architecture detection.
Searches for known function entry patterns specific to each architecture.
"""
from typing import List
from collections import Counter
from .base import BaseDetector, ArchDetectionResult


class PrologueDetector(BaseDetector):
    """
    Detect architecture by searching for function prologue patterns.
    
    Method: Count occurrences of known function entry sequences
    for each architecture. More matches = higher confidence.
    """
    
    name = "prologue"
    weight = 1.0  # Lower weight - can have false positives
    
    # Function prologue patterns by architecture
    PROLOGUE_PATTERNS = {
        "ARM32": [
            b'\x04\xe0\x2d\xe5',  # str lr, [sp, #-4]!
            b'\x00\x48\x2d\xe9',  # push {r11, lr}
            b'\xf0\x4f\x2d\xe9',  # push {r4-r11, lr}
            b'\x10\x40\x2d\xe9',  # push {r4, lr}
            b'\x30\x40\x2d\xe9',  # push {r4, r5, lr}
        ],
        "ARM-Thumb": [
            b'\x80\xb5',  # push {r7, lr}
            b'\xf0\xb5',  # push {r4-r7, lr}
            b'\x2d\xe9',  # push.w
            b'\x00\xb5',  # push {lr}
            b'\x10\xb5',  # push {r4, lr}
        ],
        "ARM64": [
            b'\xfd\x7b\xbf\xa9',  # stp x29, x30, [sp, #-16]!
            b'\xfd\x7b\x01\xa9',  # stp x29, x30, [sp, #16]
            b'\xff\x83\x00\xd1',  # sub sp, sp, #N
            b'\xfd\x03\x00\x91',  # mov x29, sp
        ],
        "x86": [
            b'\x55\x89\xe5',      # push ebp; mov ebp, esp
            b'\x55\x8b\xec',      # push ebp; mov ebp, esp (alt)
            b'\x83\xec',          # sub esp, N
            b'\x81\xec',          # sub esp, N (large)
        ],
        "x86-64": [
            b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp
            b'\x48\x83\xec',      # sub rsp, N
            b'\x48\x81\xec',      # sub rsp, N (large)
            b'\x41\x57',          # push r15
            b'\x41\x56',          # push r14
        ],
        "MIPS-BE": [
            b'\x27\xbd\xff',      # addiu sp, sp, -N
            b'\xaf\xbf',          # sw ra, N(sp)
            b'\xaf\xbe',          # sw s8, N(sp)
            b'\x00\x80\xf0\x21',  # move s8, a0
        ],
        "MIPS-LE": [
            b'\xff\xbd\x27',      # addiu sp, sp, -N (LE)
            b'\xbf\xaf',          # sw ra (LE)
            b'\xbe\xaf',          # sw s8 (LE)
        ],
        "PowerPC": [
            b'\x94\x21\xff',      # stwu r1, -N(r1)
            b'\x7c\x08\x02\xa6',  # mflr r0
            b'\x90\x01',          # stw r0, N(r1)
            b'\xbf\x81',          # stmw r28, N(r1)
        ],
        "RISCV32": [
            b'\x13\x01\x01',      # addi sp, sp, -N
            b'\x23\x34\x11',      # sd ra, N(sp)
            b'\x23\x30\x81',      # sd s0, N(sp)
        ],
    }
    
    # Minimum matches required for each architecture
    MIN_MATCHES = 3
    
    def detect(self, data: bytes, offsets: List[int] = None) -> List[ArchDetectionResult]:
        """Search for prologue patterns in binary."""
        
        # Use larger sample for pattern searching
        sample = data[:200000]  # First 200KB
        
        results = []
        
        for arch, patterns in self.PROLOGUE_PATTERNS.items():
            total_matches = 0
            pattern_details = {}
            
            for pattern in patterns:
                count = sample.count(pattern)
                if count > 0:
                    total_matches += count
                    pattern_details[pattern.hex()] = count
            
            if total_matches >= self.MIN_MATCHES:
                # Confidence based on match count (logarithmic scale)
                import math
                confidence = min(0.3 + 0.1 * math.log2(total_matches + 1), 0.85)
                
                results.append(ArchDetectionResult(
                    architecture=arch,
                    confidence=confidence,
                    bits=64 if "64" in arch else 32,
                    endian="BE" if "BE" in arch else "LE",
                    method=self.name,
                    details={
                        "total_matches": total_matches,
                        "patterns_found": len(pattern_details),
                        "pattern_counts": pattern_details
                    }
                ))
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
