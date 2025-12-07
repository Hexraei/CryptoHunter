#!/usr/bin/env python3
"""
Z80 Architecture Detection Script for CryptoHunter Framework
Detects Z80 binaries using magic bytes, opcodes, and structural analysis.

References:
- Vector35/Z80 (Binary Ninja plugin): https://github.com/Vector35/Z80
- z80dismblr: https://github.com/nicschumann/z80dismblr
- lvitals/z80dasm: https://github.com/lvitals/z80dasm
- sarnau/Z80DisAssembler: https://github.com/sarnau/Z80DisAssembler
"""

import os
import struct
from pathlib import Path
from typing import Dict, Tuple, Optional, List


# Z80 Common File Signatures and Magic Numbers
Z80_SIGNATURES = {
    # ZX Spectrum snapshot formats
    b'\x00\x5b': 'ZX Spectrum SNA (basic)',
    # Z80 snapshot format headers
    b'\x00\x00\x00': 'Potential Z80 snapshot',
}

# Z80 Hardware Vectors (common entry points)
Z80_VECTORS = {
    0x0000: 'RST 00h / RESET',
    0x0008: 'RST 08h',
    0x0010: 'RST 10h',
    0x0018: 'RST 18h',
    0x0020: 'RST 20h',
    0x0028: 'RST 28h',
    0x0030: 'RST 30h',
    0x0038: 'RST 38h / Mode 1 INT',
    0x0066: 'NMI',
}

# Z80 Characteristic Opcodes (common instruction patterns)
Z80_OPCODES = {
    # Single byte opcodes
    0x00: 'NOP',
    0x76: 'HALT',
    0xC3: 'JP nn',      # Unconditional jump
    0xCD: 'CALL nn',    # Call subroutine
    0xC9: 'RET',        # Return
    0xFB: 'EI',         # Enable interrupts
    0xF3: 'DI',         # Disable interrupts
    0xED: 'Extended',   # Extended instruction prefix
    0xDD: 'IX prefix',  # IX register operations
    0xFD: 'IY prefix',  # IY register operations
    0xCB: 'Bit ops',    # Bit operations prefix
    
    # Common PUSH/POP
    0xC5: 'PUSH BC',
    0xD5: 'PUSH DE',
    0xE5: 'PUSH HL',
    0xF5: 'PUSH AF',
    0xC1: 'POP BC',
    0xD1: 'POP DE',
    0xE1: 'POP HL',
    0xF1: 'POP AF',
    
    # Load instructions
    0x3E: 'LD A,n',
    0x06: 'LD B,n',
    0x0E: 'LD C,n',
    0x16: 'LD D,n',
    0x1E: 'LD E,n',
    0x26: 'LD H,n',
    0x2E: 'LD L,n',
    0x21: 'LD HL,nn',
    0x01: 'LD BC,nn',
    0x11: 'LD DE,nn',
    0x31: 'LD SP,nn',
}

# Extended opcodes (ED prefix)
Z80_ED_OPCODES = {
    0x47: 'LD I,A',
    0x4F: 'LD R,A',
    0x57: 'LD A,I',
    0x5F: 'LD A,R',
    0xB0: 'LDIR',      # Block copy
    0xB8: 'LDDR',
    0xB1: 'CPIR',
    0xB9: 'CPDR',
    0x46: 'IM 0',
    0x56: 'IM 1',
    0x5E: 'IM 2',
    0x4D: 'RETI',
    0x45: 'RETN',
}


class Z80Detector:
    """Detect Z80 architecture binaries."""
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.data = b''
        self.confidence = 0.0
        self.indicators: List[str] = []
        
    def load_file(self) -> bool:
        """Load binary file into memory."""
        try:
            if not self.filepath.exists():
                return False
            self.data = self.filepath.read_bytes()
            return len(self.data) > 0
        except Exception as e:
            print(f"Error loading file: {e}")
            return False
    
    def check_file_extension(self) -> float:
        """Check file extension for Z80-related formats."""
        z80_extensions = {
            '.z80': 0.8,
            '.sna': 0.8,
            '.tap': 0.6,
            '.tzx': 0.6,
            '.rom': 0.3,
            '.bin': 0.1,
        }
        ext = self.filepath.suffix.lower()
        if ext in z80_extensions:
            self.indicators.append(f"File extension: {ext}")
            return z80_extensions[ext]
        return 0.0
    
    def check_magic_bytes(self) -> float:
        """Check for Z80-specific magic bytes/signatures."""
        if len(self.data) < 4:
            return 0.0
            
        score = 0.0
        
        # Check for SNA snapshot format (49179 bytes typical)
        if len(self.data) == 49179:
            self.indicators.append("SNA snapshot size detected (49179 bytes)")
            score += 0.5
            
        # Check for Z80 snapshot header patterns
        # Z80 format: byte 0-1 = AF, byte 2-3 = BC, etc.
        if len(self.data) >= 30:
            # Z80 snapshot version check
            header_byte_12 = self.data[12] if len(self.data) > 12 else 0
            if header_byte_12 == 0:
                # Could be Z80 v1 format (PC at byte 6-7)
                pc = struct.unpack('<H', self.data[6:8])[0] if len(self.data) > 8 else 0
                if pc != 0:
                    self.indicators.append("Potential Z80 v1 snapshot header")
                    score += 0.3
                    
        return score
    
    def analyze_opcode_frequency(self, sample_size: int = 4096) -> float:
        """Analyze opcode frequency for Z80 patterns."""
        if len(self.data) < 16:
            return 0.0
            
        sample = self.data[:min(sample_size, len(self.data))]
        
        # Count Z80-specific opcodes
        opcode_counts = {op: 0 for op in Z80_OPCODES}
        ed_prefix_count = 0
        dd_prefix_count = 0
        fd_prefix_count = 0
        cb_prefix_count = 0
        
        i = 0
        while i < len(sample):
            byte = sample[i]
            
            if byte in Z80_OPCODES:
                opcode_counts[byte] += 1
                
            if byte == 0xED:
                ed_prefix_count += 1
                if i + 1 < len(sample) and sample[i + 1] in Z80_ED_OPCODES:
                    opcode_counts[byte] += 1
                i += 1
            elif byte == 0xDD:
                dd_prefix_count += 1
            elif byte == 0xFD:
                fd_prefix_count += 1
            elif byte == 0xCB:
                cb_prefix_count += 1
                
            i += 1
        
        # Calculate score based on opcode patterns
        score = 0.0
        total_opcodes = sum(opcode_counts.values())
        
        if total_opcodes > 0:
            # High frequency of Z80-specific opcodes is a strong indicator
            coverage = total_opcodes / len(sample)
            if coverage > 0.3:
                self.indicators.append(f"High Z80 opcode coverage: {coverage:.1%}")
                score += 0.4
            elif coverage > 0.15:
                self.indicators.append(f"Moderate Z80 opcode coverage: {coverage:.1%}")
                score += 0.2
                
        # Prefix byte analysis (DD, FD, ED are unique to Z80)
        prefix_total = ed_prefix_count + dd_prefix_count + fd_prefix_count
        if prefix_total > 5:
            self.indicators.append(f"Z80 prefix opcodes found: ED={ed_prefix_count}, DD={dd_prefix_count}, FD={fd_prefix_count}")
            score += 0.3
            
        return min(score, 0.6)
    
    def check_entry_point_patterns(self) -> float:
        """Check for typical Z80 entry point patterns."""
        if len(self.data) < 8:
            return 0.0
            
        score = 0.0
        
        # Check first instruction patterns
        first_byte = self.data[0]
        
        # Common Z80 startup patterns
        startup_patterns = [
            (0xF3, "DI (Disable interrupts)"),
            (0x31, "LD SP,nn (Set stack pointer)"),
            (0xC3, "JP nn (Jump)"),
            (0x3E, "LD A,n"),
            (0x21, "LD HL,nn"),
        ]
        
        for opcode, name in startup_patterns:
            if first_byte == opcode:
                self.indicators.append(f"Z80 startup pattern: {name}")
                score += 0.15
                break
                
        # Check for DI followed by LD SP pattern (very common in Z80)
        if len(self.data) >= 4:
            if self.data[0] == 0xF3 and self.data[1] == 0x31:
                self.indicators.append("Classic Z80 startup: DI + LD SP,nn")
                score += 0.3
                
        return score
    
    def check_interrupt_vectors(self) -> float:
        """Analyze interrupt vector patterns."""
        if len(self.data) < 0x67:
            return 0.0
            
        score = 0.0
        vector_hits = 0
        
        for addr, name in Z80_VECTORS.items():
            if addr < len(self.data):
                # Check if there's a sensible instruction at vector location
                byte = self.data[addr]
                if byte in [0xC3, 0x18, 0xC9, 0xFB]:  # JP, JR, RET, EI
                    vector_hits += 1
                    
        if vector_hits >= 3:
            self.indicators.append(f"Found {vector_hits} potential interrupt vectors")
            score = 0.2
            
        return score
    
    def detect(self) -> Dict:
        """Run full Z80 detection analysis."""
        if not self.load_file():
            return {
                'is_z80': False,
                'confidence': 0.0,
                'error': 'Failed to load file',
                'indicators': []
            }
            
        # Run all detection methods
        scores = [
            self.check_file_extension(),
            self.check_magic_bytes(),
            self.analyze_opcode_frequency(),
            self.check_entry_point_patterns(),
            self.check_interrupt_vectors(),
        ]
        
        self.confidence = sum(scores)
        self.confidence = min(1.0, self.confidence)
        
        return {
            'is_z80': self.confidence >= 0.5,
            'confidence': self.confidence,
            'architecture': 'Z80 (Zilog)',
            'bits': 8,
            'endianness': 'little',
            'indicators': self.indicators,
            'file_size': len(self.data),
        }


def detect_z80(filepath: str) -> Dict:
    """
    Detect if a binary file is Z80 architecture.
    
    Args:
        filepath: Path to the binary file
        
    Returns:
        Dictionary with detection results
    """
    detector = Z80Detector(filepath)
    return detector.detect()


def batch_detect_z80(directory: str, extensions: List[str] = None) -> List[Dict]:
    """
    Batch detect Z80 binaries in a directory.
    
    Args:
        directory: Path to scan
        extensions: File extensions to check (default: all)
        
    Returns:
        List of detection results for Z80 candidates
    """
    results = []
    path = Path(directory)
    
    if not path.exists():
        return results
        
    for file in path.rglob('*'):
        if file.is_file():
            if extensions and file.suffix.lower() not in extensions:
                continue
            result = detect_z80(str(file))
            if result.get('is_z80', False):
                result['filepath'] = str(file)
                results.append(result)
                
    return results


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python check_z80.py <binary_file_or_directory>")
        print("\nDetects Z80 architecture binaries using opcode analysis.")
        print("\nGitHub References:")
        print("  - Vector35/Z80: https://github.com/Vector35/Z80")
        print("  - z80dismblr: https://github.com/nicschumann/z80dismblr")
        print("  - lvitals/z80dasm: https://github.com/lvitals/z80dasm")
        sys.exit(1)
        
    target = sys.argv[1]
    
    if os.path.isfile(target):
        result = detect_z80(target)
        print(json.dumps(result, indent=2))
    elif os.path.isdir(target):
        print(f"Scanning directory: {target}")
        results = batch_detect_z80(target)
        print(f"\nFound {len(results)} Z80 candidates:")
        for r in results:
            print(f"  {r['filepath']}: {r['confidence']:.1%} confidence")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
