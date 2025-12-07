#!/usr/bin/env python3
"""
AVR Architecture Detection Script for CryptoHunter Framework
Detects AVR/Arduino binaries using magic bytes, opcodes, and structural analysis.

References:
- vsergeev/vavrdisasm: https://github.com/vsergeev/vavrdisasm
- imrehorvath/avrdis: https://github.com/imrehorvath/avrdis
- twinearthsoftware/AVRDisassembler: https://github.com/twinearthsoftware/AVRDisassembler
- IlPaoli/DisassemblerAVR: https://github.com/IlPaoli/DisassemblerAVR
- radare2 AVR support
"""

import os
import struct
from pathlib import Path
from typing import Dict, Tuple, Optional, List


# Intel HEX format markers
INTEL_HEX_START = b':'

# AVR Instruction Set - 16-bit opcodes (little-endian in memory)
# Most AVR instructions are 16 bits (2 bytes), some are 32 bits

AVR_OPCODES = {
    # NOP
    0x0000: 'NOP',
    
    # RJMP (Relative Jump) - 1100 kkkk kkkk kkkk
    # Pattern: 0xCxxx
    
    # RCALL (Relative Call) - 1101 kkkk kkkk kkkk
    # Pattern: 0xDxxx
    
    # RET - 1001 0101 0000 1000 = 0x9508
    0x9508: 'RET',
    
    # RETI - 1001 0101 0001 1000 = 0x9518
    0x9518: 'RETI',
    
    # CLI - Clear Interrupt Flag - 1001 0100 1111 1000 = 0x94F8
    0x94F8: 'CLI',
    
    # SEI - Set Interrupt Flag - 1001 0100 0111 1000 = 0x9478
    0x9478: 'SEI',
    
    # SLEEP - 1001 0101 1000 1000 = 0x9588
    0x9588: 'SLEEP',
    
    # WDR - Watchdog Reset - 1001 0101 1010 1000 = 0x95A8
    0x95A8: 'WDR',
    
    # BREAK - 1001 0101 1001 1000 = 0x9598
    0x9598: 'BREAK',
    
    # SPM - Store Program Memory - 1001 0101 1110 1000 = 0x95E8
    0x95E8: 'SPM',
    
    # LPM - Load Program Memory - 1001 0101 1100 1000 = 0x95C8
    0x95C8: 'LPM',
    
    # ELPM - 1001 0101 1101 1000 = 0x95D8
    0x95D8: 'ELPM',
    
    # IJMP - Indirect Jump - 1001 0100 0000 1001 = 0x9409
    0x9409: 'IJMP',
    
    # ICALL - Indirect Call - 1001 0101 0000 1001 = 0x9509
    0x9509: 'ICALL',
    
    # EIJMP - 1001 0100 0001 1001 = 0x9419
    0x9419: 'EIJMP',
    
    # EICALL - 1001 0101 0001 1001 = 0x9519
    0x9519: 'EICALL',
}

# Opcode masks for pattern matching (for instructions with operands)
AVR_OPCODE_MASKS = [
    # (mask, expected, name)
    (0xF000, 0xC000, 'RJMP'),    # 1100 kkkk kkkk kkkk
    (0xF000, 0xD000, 'RCALL'),   # 1101 kkkk kkkk kkkk
    (0xFC00, 0x9400, 'COM/NEG/SWAP/INC/ASR/LSR/ROR'),  # Single register ops
    (0xFC00, 0x9000, 'LDS/STS'),  # Load/Store Direct
    (0xD000, 0x8000, 'LDD/STD'),  # Load/Store with Displacement
    (0xF000, 0xE000, 'LDI'),      # Load Immediate: 1110 KKKK dddd KKKK
    (0xFC00, 0x2C00, 'MOV'),      # 0010 11rd dddd rrrr
    (0xFC00, 0x0C00, 'ADD'),      # 0000 11rd dddd rrrr
    (0xFC00, 0x1C00, 'ADC'),      # 0001 11rd dddd rrrr
    (0xFC00, 0x1800, 'SUB'),      # 0001 10rd dddd rrrr
    (0xFC00, 0x0800, 'SBC'),      # 0000 10rd dddd rrrr
    (0xFC00, 0x2000, 'AND'),      # 0010 00rd dddd rrrr
    (0xFC00, 0x2800, 'OR'),       # 0010 10rd dddd rrrr
    (0xFC00, 0x2400, 'EOR'),      # 0010 01rd dddd rrrr
    (0xFC00, 0x1400, 'CP'),       # 0001 01rd dddd rrrr
    (0xFC00, 0x0400, 'CPC'),      # 0000 01rd dddd rrrr
    (0xF000, 0x3000, 'CPI'),      # 0011 KKKK dddd KKKK
    (0xF000, 0x7000, 'ANDI'),     # 0111 KKKK dddd KKKK
    (0xF000, 0x6000, 'ORI/SBR'),  # 0110 KKKK dddd KKKK
    (0xF800, 0xF800, 'BRBS/BRBC'),# Branch on bit
    (0xFC07, 0xF400, 'BRCC/BRSH'),
    (0xFC07, 0xF000, 'BRCS/BRLO'),
    (0xFC07, 0xF001, 'BREQ'),     # Branch if Equal
    (0xFC07, 0xF401, 'BRNE'),     # Branch if Not Equal
    (0xFE0F, 0x920F, 'PUSH'),     # 1001 001d dddd 1111
    (0xFE0F, 0x900F, 'POP'),      # 1001 000d dddd 1111
    (0xFF00, 0x0100, 'MOVW'),     # 0000 0001 dddd rrrr
    (0xFF00, 0x9600, 'ADIW'),     # 1001 0110 KKdd KKKK
    (0xFF00, 0x9700, 'SBIW'),     # 1001 0111 KKdd KKKK
    (0xFE08, 0x9400, 'BSET/BCLR'),
]

# AVR Vector Table Sizes (different MCU models)
AVR_VECTOR_SIZES = {
    'ATtiny': 20,      # Small AVR
    'ATmega8': 19,
    'ATmega328': 26,   # Arduino Uno
    'ATmega2560': 57,  # Arduino Mega
}

# AVR characteristic patterns
AVR_STARTUP_PATTERNS = [
    # Reset vector typically starts with RJMP or JMP to main
    # RJMP pattern: 0xCxxx
    # JMP pattern: 0x940C or 0x940D (32-bit instruction)
]


class AVRDetector:
    """Detect AVR architecture binaries."""
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.data = b''
        self.confidence = 0.0
        self.indicators: List[str] = []
        self.is_intel_hex = False
        
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
        """Check file extension for AVR-related formats."""
        avr_extensions = {
            '.hex': 0.6,      # Intel HEX format (common for AVR)
            '.ihex': 0.6,
            '.eep': 0.7,      # EEPROM data
            '.elf': 0.3,      # Could be any arch
            '.bin': 0.1,
            '.o': 0.2,
        }
        ext = self.filepath.suffix.lower()
        if ext in avr_extensions:
            self.indicators.append(f"File extension: {ext}")
            return avr_extensions[ext]
        return 0.0
    
    def check_intel_hex_format(self) -> float:
        """Check if file is in Intel HEX format (common for AVR)."""
        if len(self.data) == 0:
            return 0.0
            
        # Check for Intel HEX start character
        if self.data[0:1] == b':':
            # Verify format: :LLAAAATT[DD...]CC
            lines = self.data.split(b'\n')
            valid_lines = 0
            
            for line in lines[:10]:  # Check first 10 lines
                line = line.strip()
                if len(line) == 0:
                    continue
                if line.startswith(b':'):
                    try:
                        # Try to parse as Intel HEX
                        if len(line) >= 11:
                            byte_count = int(line[1:3], 16)
                            expected_len = 1 + 2 + 4 + 2 + (byte_count * 2) + 2
                            if len(line) >= expected_len:
                                valid_lines += 1
                    except ValueError:
                        pass
                        
            if valid_lines >= 3:
                self.is_intel_hex = True
                self.indicators.append("Intel HEX format detected (common for AVR)")
                return 0.4
                
        return 0.0
    
    def parse_intel_hex_to_binary(self) -> bytes:
        """Convert Intel HEX to raw binary for analysis."""
        if not self.is_intel_hex:
            return self.data
            
        binary_data = bytearray()
        lines = self.data.split(b'\n')
        
        for line in lines:
            line = line.strip()
            if not line.startswith(b':'):
                continue
            if len(line) < 11:
                continue
                
            try:
                byte_count = int(line[1:3], 16)
                record_type = int(line[7:9], 16)
                
                # Only process data records (type 00)
                if record_type == 0x00:
                    data_hex = line[9:9 + byte_count * 2]
                    for i in range(0, len(data_hex), 2):
                        binary_data.append(int(data_hex[i:i+2], 16))
            except (ValueError, IndexError):
                continue
                
        return bytes(binary_data)
    
    def analyze_opcode_frequency(self, sample_size: int = 4096) -> float:
        """Analyze opcode frequency for AVR patterns."""
        # Get binary data
        binary_data = self.parse_intel_hex_to_binary()
        
        if len(binary_data) < 4:
            return 0.0
            
        sample = binary_data[:min(sample_size, len(binary_data))]
        
        # AVR uses 16-bit (2 byte) instructions, little-endian
        if len(sample) % 2 != 0:
            sample = sample[:-1]
            
        opcode_hits = 0
        pattern_hits = 0
        rjmp_count = 0
        rcall_count = 0
        ret_count = 0
        ldi_count = 0
        
        i = 0
        while i < len(sample) - 1:
            # Read 16-bit instruction (little-endian)
            opcode = struct.unpack('<H', sample[i:i+2])[0]
            
            # Check exact matches
            if opcode in AVR_OPCODES:
                opcode_hits += 1
                if opcode == 0x9508:
                    ret_count += 1
                    
            # Check pattern matches
            for mask, expected, name in AVR_OPCODE_MASKS:
                if (opcode & mask) == expected:
                    pattern_hits += 1
                    if name == 'RJMP':
                        rjmp_count += 1
                    elif name == 'RCALL':
                        rcall_count += 1
                    elif name == 'LDI':
                        ldi_count += 1
                    break
                    
            i += 2
        
        score = 0.0
        total_instructions = len(sample) // 2
        
        if total_instructions > 0:
            # Pattern coverage
            coverage = (opcode_hits + pattern_hits) / total_instructions
            
            if coverage > 0.5:
                self.indicators.append(f"High AVR instruction coverage: {coverage:.1%}")
                score += 0.4
            elif coverage > 0.25:
                self.indicators.append(f"Moderate AVR instruction coverage: {coverage:.1%}")
                score += 0.2
                
            # RJMP/RCALL are very common in AVR
            if rjmp_count > 3:
                self.indicators.append(f"RJMP instructions found: {rjmp_count}")
                score += 0.1
            if rcall_count > 3:
                self.indicators.append(f"RCALL instructions found: {rcall_count}")
                score += 0.1
            if ldi_count > 5:
                self.indicators.append(f"LDI (Load Immediate) instructions: {ldi_count}")
                score += 0.1
                
        return min(score, 0.6)
    
    def check_vector_table(self) -> float:
        """Check for AVR interrupt vector table patterns."""
        binary_data = self.parse_intel_hex_to_binary()
        
        if len(binary_data) < 8:
            return 0.0
            
        score = 0.0
        
        # AVR vector table typically starts with RJMP instructions
        # RJMP format: 0xCxxx (1100 kkkk kkkk kkkk)
        rjmp_vectors = 0
        jmp_vectors = 0
        
        # Check first 26 vectors (Arduino Uno has 26)
        for i in range(0, min(len(binary_data), 26 * 4), 4):
            if i + 1 >= len(binary_data):
                break
                
            opcode = struct.unpack('<H', binary_data[i:i+2])[0]
            
            # Check for RJMP (0xCxxx)
            if (opcode & 0xF000) == 0xC000:
                rjmp_vectors += 1
                
            # Check for JMP (32-bit: 0x940C/0x940D followed by address)
            if opcode in [0x940C, 0x940D]:
                jmp_vectors += 1
                
        # AVR typically has many RJMP in vector table
        if rjmp_vectors >= 5:
            self.indicators.append(f"AVR vector table pattern: {rjmp_vectors} RJMP vectors")
            score += 0.3
        elif jmp_vectors >= 3:
            self.indicators.append(f"AVR vector table pattern: {jmp_vectors} JMP vectors (larger MCU)")
            score += 0.25
            
        return score
    
    def check_flash_size_patterns(self) -> float:
        """Check if binary size matches common AVR flash sizes."""
        binary_data = self.parse_intel_hex_to_binary()
        size = len(binary_data)
        
        # Common AVR flash sizes (in bytes)
        avr_flash_sizes = {
            1024: 'ATtiny13',
            2048: 'ATtiny25',
            4096: 'ATtiny45',
            8192: 'ATtiny85/ATmega8',
            16384: 'ATmega168',
            32768: 'ATmega328 (Arduino Uno)',
            65536: 'ATmega644',
            131072: 'ATmega1284',
            262144: 'ATmega2560 (Arduino Mega)',
        }
        
        for flash_size, mcu in avr_flash_sizes.items():
            # Check if size is close to a known flash size
            if 0.5 <= size / flash_size <= 1.0:
                self.indicators.append(f"Size matches {mcu} flash range")
                return 0.15
                
        return 0.0
    
    def detect(self) -> Dict:
        """Run full AVR detection analysis."""
        if not self.load_file():
            return {
                'is_avr': False,
                'confidence': 0.0,
                'error': 'Failed to load file',
                'indicators': []
            }
            
        # Run all detection methods
        scores = [
            self.check_file_extension(),
            self.check_intel_hex_format(),
            self.analyze_opcode_frequency(),
            self.check_vector_table(),
            self.check_flash_size_patterns(),
        ]
        
        self.confidence = sum(scores)
        self.confidence = min(1.0, self.confidence)
        
        binary_data = self.parse_intel_hex_to_binary()
        
        return {
            'is_avr': self.confidence >= 0.5,
            'confidence': self.confidence,
            'architecture': 'AVR (Atmel/Microchip)',
            'bits': 8,
            'endianness': 'little',
            'is_intel_hex': self.is_intel_hex,
            'indicators': self.indicators,
            'file_size': len(self.data),
            'binary_size': len(binary_data),
        }


def detect_avr(filepath: str) -> Dict:
    """
    Detect if a binary file is AVR architecture.
    
    Args:
        filepath: Path to the binary file
        
    Returns:
        Dictionary with detection results
    """
    detector = AVRDetector(filepath)
    return detector.detect()


def batch_detect_avr(directory: str, extensions: List[str] = None) -> List[Dict]:
    """
    Batch detect AVR binaries in a directory.
    
    Args:
        directory: Path to scan
        extensions: File extensions to check (default: all)
        
    Returns:
        List of detection results for AVR candidates
    """
    results = []
    path = Path(directory)
    
    if not path.exists():
        return results
        
    for file in path.rglob('*'):
        if file.is_file():
            if extensions and file.suffix.lower() not in extensions:
                continue
            result = detect_avr(str(file))
            if result.get('is_avr', False):
                result['filepath'] = str(file)
                results.append(result)
                
    return results


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python check_avr.py <binary_file_or_directory>")
        print("\nDetects AVR/Arduino architecture binaries using opcode analysis.")
        print("\nGitHub References:")
        print("  - vsergeev/vavrdisasm: https://github.com/vsergeev/vavrdisasm")
        print("  - imrehorvath/avrdis: https://github.com/imrehorvath/avrdis")
        print("  - twinearthsoftware/AVRDisassembler: https://github.com/twinearthsoftware/AVRDisassembler")
        print("  - radare2 AVR support")
        sys.exit(1)
        
    target = sys.argv[1]
    
    if os.path.isfile(target):
        result = detect_avr(target)
        print(json.dumps(result, indent=2))
    elif os.path.isdir(target):
        print(f"Scanning directory: {target}")
        results = batch_detect_avr(target)
        print(f"\nFound {len(results)} AVR candidates:")
        for r in results:
            print(f"  {r['filepath']}: {r['confidence']:.1%} confidence")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
