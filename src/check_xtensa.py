#!/usr/bin/env python3
"""
Xtensa Architecture Detection Script for CryptoHunter Framework
Detects Xtensa/ESP32/ESP8266 binaries using opcodes and structural analysis.
Works with STRIPPED firmware (no headers).

Xtensa is Cadence's configurable processor, commonly used in:
- ESP32/ESP8266 (Espressif IoT chips)
- Some DSPs and embedded systems
- 32-bit RISC-like with variable-length instructions (16/24-bit)

References:
- Espressif ESP-IDF: https://github.com/espressif/esp-idf
- Xtensa ISA reference (Cadence)
- Ghidra Xtensa: https://github.com/yath/ghidra-xtensa
- radare2 xtensa support
"""

import os
import struct
from pathlib import Path
from typing import Dict, List


# ================================================================
# Xtensa Instruction Set - Variable Length (16-bit and 24-bit)
# ================================================================

# Xtensa uses LITTLE ENDIAN encoding
# Most common instruction formats:
# - NARROW (16-bit): compressed instructions, opcode in bits [3:0]
# - WIDE (24-bit): full instructions, opcode in bits [3:0] and bits [23:20]

# Common 24-bit Xtensa Opcodes (first byte patterns)
# Format: QRST_op0 where op0 is in bits [3:0]
XTENSA_24BIT_OPCODES = {
    # CALL instructions (very common in Xtensa code)
    # CALL0: 0000 0101 (op0=0101 = 5)
    0x05: 'CALL0/CALLX0',
    # CALL4: 0010 0101
    0x25: 'CALL4',
    # CALL8: 0100 0101
    0x45: 'CALL8',
    # CALL12: 0110 0101
    0x65: 'CALL12',
    
    # Entry instruction (function prologue) - VERY characteristic of Xtensa
    # ENTRY: op0=0110 (6), op1=0011
    0x36: 'ENTRY',  # 0011 0110
    
    # Return instructions
    # RETW: op0=0000, subop for window return
    # RET: 1000 0000 (0x80 in narrow format)
    
    # Load/Store instructions (op0 = 2 for loads, op0 = 2 for stores)
    0x02: 'L8UI/L16SI/L32I',  # Load instructions
    0x22: 'L16UI',
    0x42: 'L32I.N (narrow)',
    
    # Store instructions
    0x62: 'S32I.N (narrow)',
    
    # Branch instructions
    0x06: 'J (jump)',          # Unconditional jump
    0x16: 'BZ/BNZ/BEQZ/BNEZ',  # Conditional branches
    0x26: 'BEQI/BNEI/BLTI',    # Immediate compare & branch
    0x56: 'BBCI/BBSI',         # Bit branch
    0x76: 'BEQ/BNE/BLT/BGE',   # Register compare & branch
    
    # Move and immediate
    0x0C: 'MOVI.N',   # Move immediate (narrow)
    0xA2: 'MOVI',     # Move immediate
    
    # Arithmetic
    0x00: 'ADD/SUB/AND/OR/XOR',  # ALU operations (determined by upper bits)
    0x10: 'ADDMI',
    0x80: 'ADD.N',
    0x90: 'ADDI.N',
}

# 16-bit (Narrow) Xtensa opcodes - these are compressed instructions
XTENSA_16BIT_OPCODES = {
    # Narrow instructions have op0 in bits [3:0] of first byte
    # Format: .... op0 (op0 = bits [3:0])
    
    # Common narrow instructions (2 bytes)
    0x0D: 'MOV.N',      # Move narrow
    0x1D: 'MOVI.N',     # Move immediate narrow
    0x0C: 'MOVI.N',     # Alternate encoding
    0x0A: 'ADD.N',      # Add narrow
    0x0B: 'ADDI.N',     # Add immediate narrow
    0x08: 'L32I.N',     # Load 32-bit narrow
    0x09: 'S32I.N',     # Store 32-bit narrow
    0x8D: 'RETW.N',     # Return with windowed
    0x0F: 'RET.N',      # Return narrow (actually RETW.N = 0xF01D)
}

# ESP32/ESP8266 firmware magic bytes
ESP_MAGIC = {
    b'\xe9\x00': 'ESP8266 bootloader',
    b'\xe9\x02': 'ESP32 application',
    b'\xe9\x03': 'ESP32-S2 application',
    b'\xe9\x04': 'ESP32-C3 (RISC-V, not Xtensa!)',
    b'\xe9\x05': 'ESP32-S3 application',
}

# Common Xtensa constants/patterns in code
XTENSA_PATTERNS = {
    # Window save area marker (entry instruction typically uses this)
    b'\x36': 'ENTRY opcode',
    # Common ESP-IDF strings
    b'esp_': 'ESP-IDF function prefix',
    b'ESP-IDF': 'ESP-IDF framework marker',
    b'ESPTOOL': 'ESP flashing tool marker',
    b'wifi_': 'ESP WiFi functions',
    b'ble_': 'ESP BLE functions',
    b'gpio_': 'ESP GPIO functions',
}


class XtensaDetector:
    """Detect Xtensa architecture binaries (ESP32/ESP8266/Xtensa DSP)."""
    
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
        """Check file extension for Xtensa-related formats."""
        xtensa_extensions = {
            '.bin': 0.1,      # Generic binary
            '.elf': 0.2,      # Could be Xtensa ELF
            '.app': 0.3,      # ESP application
            '.flash': 0.4,    # Flash dump
        }
        ext = self.filepath.suffix.lower()
        if ext in xtensa_extensions:
            self.indicators.append(f"File extension: {ext}")
            return xtensa_extensions[ext]
        return 0.0
    
    def check_esp_magic(self) -> float:
        """Check for ESP32/ESP8266 magic bytes in header."""
        if len(self.data) < 16:
            return 0.0
            
        score = 0.0
        header = self.data[:2]
        
        # ESP image header format:
        # Byte 0: Magic (0xE9)
        # Byte 1: Segment count
        # Byte 12-13: Chip ID (ESP32=0, ESP32-S2=2, ESP32-C3=5, ESP32-S3=9, ESP32-C2=12)
        
        if self.data[0] == 0xE9:
            # This is an ESP firmware image
            chip_id = self.data[12] if len(self.data) > 12 else 0
            
            chip_names = {
                0: ("ESP32", True),         # Xtensa LX6
                2: ("ESP32-S2", True),      # Xtensa LX7
                5: ("ESP32-C3", False),     # RISC-V! Not Xtensa
                9: ("ESP32-S3", True),      # Xtensa LX7
                12: ("ESP32-C2", False),    # RISC-V! Not Xtensa
                13: ("ESP32-C6", False),    # RISC-V! Not Xtensa
            }
            
            if chip_id in chip_names:
                chip_name, is_xtensa = chip_names[chip_id]
                self.indicators.append(f"ESP magic detected: {chip_name} (chip ID={chip_id})")
                
                if not is_xtensa:
                    self.indicators.append(f"WARNING: {chip_name} uses RISC-V, not Xtensa!")
                    return -1.5  # Strong negative score to reject RISC-V
                else:
                    score = 0.5
            else:
                self.indicators.append(f"ESP magic detected (unknown chip ID={chip_id})")
                score = 0.3
        elif header in ESP_MAGIC:
            magic_name = ESP_MAGIC[header]
            self.indicators.append(f"ESP magic detected: {magic_name}")
            if 'RISC-V' in magic_name:
                self.indicators.append("Warning: This is RISC-V, not Xtensa!")
                return -1.5  # Strong negative score to reject RISC-V
            score = 0.5
            
        # Check for ESP-IDF marker strings
        if b'ESP-IDF' in self.data[:4096]:
            self.indicators.append("ESP-IDF framework marker found")
            score += 0.2
            
        return score
    
    def check_elf_xtensa(self) -> float:
        """Check if ELF file with Xtensa machine type."""
        if len(self.data) < 20:
            return 0.0
            
        # ELF magic
        if self.data[:4] != b'\x7fELF':
            return 0.0
            
        # e_machine at offset 18-19 (little endian)
        e_machine = struct.unpack('<H', self.data[18:20])[0]
        
        # EM_XTENSA = 94
        if e_machine == 94:
            self.indicators.append("ELF e_machine = 94 (EM_XTENSA)")
            return 0.7
            
        return 0.0
    
    def analyze_opcode_frequency(self, sample_size: int = 8192) -> float:
        """
        Analyze opcode frequency for Xtensa patterns.
        This is the KEY function for STRIPPED binaries.
        """
        if len(self.data) < 16:
            return 0.0
            
        sample = self.data[:min(sample_size, len(self.data))]
        
        # Xtensa-specific opcode counters
        entry_count = 0       # ENTRY instruction (0x36) - VERY characteristic
        call_count = 0        # CALL0/CALL4/CALL8/CALL12
        retw_count = 0        # RETW (return with window)
        load_store_count = 0  # L32I.N, S32I.N
        branch_count = 0      # Conditional branches
        narrow_count = 0      # Narrow (16-bit) instructions
        
        # Xtensa has variable length instructions: 16-bit (narrow) and 24-bit
        # We need to detect the opcode patterns
        
        i = 0
        while i < len(sample) - 2:
            byte0 = sample[i]
            byte1 = sample[i + 1] if i + 1 < len(sample) else 0
            byte2 = sample[i + 2] if i + 2 < len(sample) else 0
            
            # ENTRY instruction is VERY characteristic of Xtensa
            # Format: 0x36 in the encoding (entry a_s, imm12)
            # Entry encodes as: 0bxxxx_0110_xxxx_xxxx_xxxx_xxxx (op0=6)
            if (byte0 & 0x0F) == 0x06 and (byte0 >> 4) == 0x03:
                entry_count += 1
                i += 3
                continue
                
            # Check for CALL instructions
            # CALL0 = op0=5, CALL4/8/12 have similar patterns
            if (byte0 & 0x0F) == 0x05:
                call_count += 1
                i += 3
                continue
                
            # Check for RETW.N (return with window, narrow)
            # Encoding: 0xF01D (little endian: 0x1D 0xF0)
            if byte0 == 0x1D and byte1 == 0xF0:
                retw_count += 1
                i += 2
                continue
            
            # RET.N: 0x000D (actually complicated, but 0x0D is common)
            # RETW.N: 0xF01D
            if byte0 == 0x0D and (byte1 & 0xF0) == 0x00:
                retw_count += 1
                narrow_count += 1
                i += 2
                continue
                
            # L32I.N (narrow load): encoding 0x08 pattern
            if (byte0 & 0x0F) == 0x08:
                load_store_count += 1
                narrow_count += 1
                i += 2
                continue
                
            # S32I.N (narrow store): encoding 0x09 pattern
            if (byte0 & 0x0F) == 0x09:
                load_store_count += 1
                narrow_count += 1
                i += 2
                continue
                
            # MOV.N, MOVI.N: 0x0D, 0x1D patterns
            if byte0 in [0x0D, 0x1D, 0x0C, 0x2D]:
                narrow_count += 1
                i += 2
                continue
                
            # J (unconditional jump): op0=6
            if (byte0 & 0x0F) == 0x06:
                branch_count += 1
                i += 3
                continue
                
            # BZ/BNZ/Branch instructions: various op0 values
            if (byte0 & 0x0F) in [0x16, 0x26, 0x56, 0x76]:
                branch_count += 1
                i += 3
                continue
            
            i += 1
        
        # Calculate score based on Xtensa-specific patterns
        score = 0.0
        
        # ENTRY is THE defining instruction for Xtensa windowed ABI
        if entry_count >= 3:
            self.indicators.append(f"ENTRY instructions found: {entry_count} (windowed ABI)")
            score += 0.35
        elif entry_count >= 1:
            self.indicators.append(f"ENTRY instruction found: {entry_count}")
            score += 0.15
            
        # CALL instructions are very common
        if call_count >= 5:
            self.indicators.append(f"CALL instructions found: {call_count}")
            score += 0.15
            
        # RETW (return with window) is Xtensa-specific
        if retw_count >= 3:
            self.indicators.append(f"RETW instructions found: {retw_count}")
            score += 0.2
        elif retw_count >= 1:
            self.indicators.append(f"RETW instruction found: {retw_count}")
            score += 0.1
            
        # Narrow instructions indicate Xtensa with density option
        if narrow_count >= 10:
            self.indicators.append(f"Narrow (16-bit) instructions: {narrow_count}")
            score += 0.15
            
        # Load/store narrow format
        if load_store_count >= 5:
            self.indicators.append(f"L32I.N/S32I.N instructions: {load_store_count}")
            score += 0.1
            
        return min(score, 0.7)
    
    def check_window_register_patterns(self) -> float:
        """
        Check for Xtensa windowed register ABI patterns.
        Xtensa uses a register window of 16 visible registers (a0-a15)
        with a rotating window mechanism.
        """
        if len(self.data) < 64:
            return 0.0
            
        score = 0.0
        
        # Look for patterns that suggest windowed register usage
        # In stripped binary, we look for instruction sequences
        
        sample = self.data[:4096]
        
        # Count potential ENTRY + RETW pairs (function prologue/epilogue)
        entry_retw_pairs = 0
        
        # Simple heuristic: ENTRY followed eventually by RETW
        # ENTRY byte pattern: 0x_6 (op0=6, high nibble = 3)
        entries = []
        for i in range(len(sample) - 3):
            if (sample[i] & 0x0F) == 0x06 and (sample[i] >> 4) == 0x03:
                entries.append(i)
        
        if len(entries) >= 5:
            self.indicators.append(f"Windowed function prologues detected: {len(entries)}")
            score += 0.15
            
        return score
    
    def check_esp_sdk_strings(self) -> float:
        """Check for ESP-IDF/SDK strings in binary."""
        if len(self.data) < 100:
            return 0.0
            
        score = 0.0
        sdk_markers = [
            (b'esp_', "ESP function prefix"),
            (b'wifi_', "WiFi functions"),
            (b'esp_wifi', "ESP WiFi module"),
            (b'esp_event', "ESP event system"),
            (b'gpio_', "GPIO functions"),
            (b'i2c_', "I2C functions"),
            (b'spi_', "SPI functions"),
            (b'uart_', "UART functions"),
            (b'ble_', "BLE functions"),
            (b'bt_', "Bluetooth functions"),
            (b'nvs_', "NVS storage"),
            (b'http', "HTTP functions"),
            (b'esp_err', "ESP error handling"),
            (b'freertos', "FreeRTOS"),
            (b'FreeRTOS', "FreeRTOS"),
            (b'xTask', "FreeRTOS task"),
            (b'xQueue', "FreeRTOS queue"),
        ]
        
        found_markers = []
        for pattern, name in sdk_markers:
            if pattern in self.data:
                found_markers.append(name)
                
        if len(found_markers) >= 5:
            self.indicators.append(f"ESP-IDF SDK markers found: {', '.join(found_markers[:5])}")
            score += 0.25
        elif len(found_markers) >= 2:
            self.indicators.append(f"ESP-IDF SDK markers: {', '.join(found_markers)}")
            score += 0.15
        elif len(found_markers) >= 1:
            self.indicators.append(f"Possible ESP marker: {found_markers[0]}")
            score += 0.05
            
        return score
    
    def check_not_riscv(self) -> float:
        """
        Check for RISC-V patterns and return NEGATIVE score if found.
        This prevents false positives on ESP32-C3 (RISC-V) binaries.
        
        RISC-V has distinctive instruction patterns different from Xtensa:
        - 32-bit fixed-width instructions (vs Xtensa's 16/24-bit variable)
        - Different opcode encoding in bits [6:0]
        """
        if len(self.data) < 64:
            return 0.0
            
        sample = self.data[:8192]
        
        # RISC-V 32-bit instruction opcodes (bits [6:0])
        # Key RISC-V opcodes that are distinctive:
        riscv_lui = 0      # LUI: opcode = 0b0110111 (0x37)
        riscv_auipc = 0    # AUIPC: opcode = 0b0010111 (0x17)
        riscv_jal = 0      # JAL: opcode = 0b1101111 (0x6F)
        riscv_jalr = 0     # JALR: opcode = 0b1100111 (0x67)
        riscv_branch = 0   # Branch: opcode = 0b1100011 (0x63)
        riscv_load = 0     # Load: opcode = 0b0000011 (0x03)
        riscv_store = 0    # Store: opcode = 0b0100011 (0x23)
        riscv_alu = 0      # ALU-I: opcode = 0b0010011 (0x13)
        riscv_alu_r = 0    # ALU-R: opcode = 0b0110011 (0x33)
        
        # Scan for RISC-V opcode patterns
        # RISC-V instructions are 32-bit aligned
        for i in range(0, len(sample) - 4, 4):
            byte0 = sample[i]
            opcode = byte0 & 0x7F  # RISC-V opcode is in bits [6:0]
            
            if opcode == 0x37:  # LUI
                riscv_lui += 1
            elif opcode == 0x17:  # AUIPC - very common in RISC-V
                riscv_auipc += 1
            elif opcode == 0x6F:  # JAL
                riscv_jal += 1
            elif opcode == 0x67:  # JALR
                riscv_jalr += 1
            elif opcode == 0x63:  # Branch (BEQ, BNE, etc.)
                riscv_branch += 1
            elif opcode == 0x03:  # Load (LB, LH, LW, etc.)
                riscv_load += 1
            elif opcode == 0x23:  # Store (SB, SH, SW, etc.)
                riscv_store += 1
            elif opcode == 0x13:  # ALU immediate (ADDI, etc.)
                riscv_alu += 1
            elif opcode == 0x33:  # ALU register (ADD, SUB, etc.)
                riscv_alu_r += 1
        
        # Calculate RISC-V score
        total_riscv = (riscv_lui + riscv_auipc + riscv_jal + riscv_jalr + 
                       riscv_branch + riscv_load + riscv_store + 
                       riscv_alu + riscv_alu_r)
        
        total_instructions = len(sample) // 4
        
        if total_instructions > 0:
            riscv_coverage = total_riscv / total_instructions
            
            # If significant RISC-V patterns found, this is NOT Xtensa
            # AUIPC is especially distinctive - Xtensa doesn't use it
            # Note: Random noise can create occasional AUIPC matches, so use high thresholds
            if riscv_auipc >= 50 or riscv_coverage > 0.5:
                self.indicators.append(f"RISC-V patterns detected (AUIPC={riscv_auipc}, coverage={riscv_coverage:.1%}) - NOT Xtensa!")
                return -1.0  # Strong negative to override Xtensa detection
            
            # Only penalize if RISC-V is very strong (high AUIPC count)
            if riscv_auipc >= 30 or riscv_coverage > 0.35:
                self.indicators.append(f"Possible RISC-V (AUIPC={riscv_auipc}) - may not be Xtensa")
                return -0.3  # Reduced penalty
        
        return 0.0
    
    def detect(self) -> Dict:
        """Run full Xtensa detection analysis."""
        if not self.load_file():
            return {
                'is_xtensa': False,
                'confidence': 0.0,
                'error': 'Failed to load file',
                'indicators': []
            }
            
        # Run all detection methods
        scores = [
            self.check_file_extension(),
            self.check_esp_magic(),
            self.check_elf_xtensa(),
            self.analyze_opcode_frequency(),      # KEY for stripped binaries
            self.check_window_register_patterns(),
            self.check_esp_sdk_strings(),
            self.check_not_riscv(),               # NEGATIVE filter for RISC-V
        ]
        
        self.confidence = sum(scores)
        self.confidence = max(0.0, min(1.0, self.confidence))  # Clamp to [0, 1]
        
        # Determine variant
        variant = "Xtensa"
        if any('ESP32' in ind for ind in self.indicators):
            variant = "Xtensa/ESP32"
        elif any('ESP8266' in ind for ind in self.indicators):
            variant = "Xtensa/ESP8266"
        elif any('ESP-IDF' in ind or 'ESP' in ind for ind in self.indicators):
            variant = "Xtensa/ESP"
            
        return {
            'is_xtensa': self.confidence >= 0.5,
            'confidence': self.confidence,
            'architecture': variant,
            'bits': 32,
            'endianness': 'little',
            'indicators': self.indicators,
            'file_size': len(self.data),
        }


def detect_xtensa(filepath: str) -> Dict:
    """
    Detect if a binary file is Xtensa architecture.
    
    Args:
        filepath: Path to the binary file
        
    Returns:
        Dictionary with detection results
    """
    detector = XtensaDetector(filepath)
    return detector.detect()


def batch_detect_xtensa(directory: str, extensions: List[str] = None) -> List[Dict]:
    """
    Batch detect Xtensa binaries in a directory.
    
    Args:
        directory: Path to scan
        extensions: File extensions to check (default: all)
        
    Returns:
        List of detection results for Xtensa candidates
    """
    results = []
    path = Path(directory)
    
    if not path.exists():
        return results
        
    for file in path.rglob('*'):
        if file.is_file():
            if extensions and file.suffix.lower() not in extensions:
                continue
            result = detect_xtensa(str(file))
            if result.get('is_xtensa', False):
                result['filepath'] = str(file)
                results.append(result)
                
    return results


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python check_xtensa.py <binary_file_or_directory>")
        print("\nDetects Xtensa/ESP32/ESP8266 architecture binaries.")
        print("Works with STRIPPED firmware (no headers) using opcode analysis.")
        print("\nKey Detection Methods:")
        print("  - ENTRY instruction analysis (windowed ABI)")
        print("  - CALL/RETW instruction patterns")
        print("  - Narrow instruction frequency")
        print("  - ESP-IDF SDK string detection")
        print("\nReferences:")
        print("  - Espressif ESP-IDF: https://github.com/espressif/esp-idf")
        print("  - Ghidra Xtensa: https://github.com/yath/ghidra-xtensa")
        sys.exit(1)
        
    target = sys.argv[1]
    
    if os.path.isfile(target):
        result = detect_xtensa(target)
        print(json.dumps(result, indent=2))
    elif os.path.isdir(target):
        print(f"Scanning directory: {target}")
        results = batch_detect_xtensa(target)
        print(f"\nFound {len(results)} Xtensa candidates:")
        for r in results:
            print(f"  {r['filepath']}: {r['confidence']:.1%} confidence")
    else:
        print(f"Error: {target} not found")
        sys.exit(1)
