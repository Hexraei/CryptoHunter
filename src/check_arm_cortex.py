#!/usr/bin/env python3
"""
ARM Cortex-M Architecture Detection Script for CryptoHunter Framework
Detects ARM Cortex-M0/M3/M4 binaries using opcodes and structural analysis.
Works with STRIPPED firmware (no headers).

ARM Cortex-M is ARM's embedded processor family, commonly used in:
- STM32 (STMicroelectronics)
- nRF52/nRF53 (Nordic Semiconductor)
- LPC (NXP)
- SAMD (Microchip/Atmel)
- Many embedded systems and IoT devices

Key characteristics:
- Thumb/Thumb-2 instruction set (16-bit and 32-bit mixed)
- Vector table at address 0 with Initial SP and Reset Handler
- Little-endian (typically)

References:
- ARM Cortex-M Technical Reference Manual
- ARM v7-M Architecture Reference Manual
"""

import os
import struct
from pathlib import Path
from typing import Dict, List, Tuple


# ================================================================
# ARM Cortex-M Instruction Set - Thumb/Thumb-2
# ================================================================

# Cortex-M uses LITTLE ENDIAN encoding
# Instruction formats:
# - 16-bit Thumb instructions
# - 32-bit Thumb-2 instructions (two halfwords)

# Common 16-bit Thumb opcodes (first byte patterns in little-endian)
THUMB_16BIT_OPCODES = {
    # Function prologue - PUSH {rx, ..., LR}
    # PUSH encoding: 1011 010x xxxx xxxx
    # Low byte: reglist, High byte: 0xB4 or 0xB5 (0xB5 = includes LR)
    0xB5: 'PUSH {.., LR}',    # Very common function prologue
    0xB4: 'PUSH {..}',        # PUSH without LR
    
    # Function epilogue - POP {rx, ..., PC}
    # POP encoding: 1011 110x xxxx xxxx
    0xBD: 'POP {.., PC}',     # Very common function epilogue
    0xBC: 'POP {..}',         # POP without PC
    
    # Move instructions
    0x46: 'MOV (high reg)',   # MOV Rd, Rm (high registers)
    0x20: 'MOVS Rd, #imm8',   # Move immediate to R0
    0x21: 'MOVS R1, #imm8',
    0x22: 'MOVS R2, #imm8',
    0x23: 'MOVS R3, #imm8',
    
    # Load/Store
    0x68: 'LDR Rt, [Rn, #imm5]',   # Load word
    0x60: 'STR Rt, [Rn, #imm5]',   # Store word
    0x78: 'LDRB Rt, [Rn, #imm5]',  # Load byte
    0x70: 'STRB Rt, [Rn, #imm5]',  # Store byte
    0x88: 'LDRH Rt, [Rn, #imm5]',  # Load halfword
    0x80: 'STRH Rt, [Rn, #imm5]',  # Store halfword
    
    # PC-relative load (very common in Cortex-M)
    0x48: 'LDR R0, [PC, #imm8]',   # Literal pool load R0
    0x49: 'LDR R1, [PC, #imm8]',
    0x4A: 'LDR R2, [PC, #imm8]',
    0x4B: 'LDR R3, [PC, #imm8]',
    0x4C: 'LDR R4, [PC, #imm8]',
    0x4D: 'LDR R5, [PC, #imm8]',
    0x4E: 'LDR R6, [PC, #imm8]',
    0x4F: 'LDR R7, [PC, #imm8]',
    
    # Branch instructions
    0xD0: 'BEQ/BNE (cond)',   # Conditional branch
    0xD1: 'BNE',
    0xD2: 'BCS/BHS',
    0xD3: 'BCC/BLO',
    0xDA: 'BGE',
    0xDB: 'BLT',
    0xDC: 'BGT',
    0xDD: 'BLE',
    0xE0: 'B (uncond)',       # Unconditional branch
    
    # Add/Sub
    0x18: 'ADDS Rd, Rn, Rm',
    0x1A: 'SUBS Rd, Rn, Rm',
    0x1C: 'ADDS Rd, Rn, #imm3',
    0x1E: 'SUBS Rd, Rn, #imm3',
    0x30: 'ADDS Rd, #imm8',   # ADD R0, #imm8
    0x38: 'SUBS Rd, #imm8',   # SUB R0, #imm8
    
    # Compare
    0x28: 'CMP R0, #imm8',
    0x29: 'CMP R1, #imm8',
    0x2A: 'CMP R2, #imm8',
    0x2B: 'CMP R3, #imm8',
    
    # Logical
    0x40: 'AND/EOR/LSL/LSR/ASR/ADC',  # Data processing
    
    # Special
    0x47: 'BX/BLX',           # Branch and exchange
    0xBE: 'BKPT',             # Breakpoint
    0xBF: 'NOP/IT',           # NOP or IT block
}

# 32-bit Thumb-2 instruction prefixes
THUMB2_32BIT_PREFIXES = {
    # BL (Branch with Link) - function call
    # Encoding: 11110xxx xxxxxxxx 11111xxx xxxxxxxx
    0xF0: 'BL/BLX prefix',    # 32-bit branch
    0xF8: 'LDR/STR (32-bit)', # Wide load/store
    0xF2: 'MOVW/MOVT',        # Wide move
    0xF3: 'MSR/MRS',          # System register access
    0xF4: 'AND/BIC (32-bit)', # Wide logical
    0xFB: 'MUL/SMULL/UMULL',  # Multiply
}

# Cortex-M specific patterns
CORTEX_M_PATTERNS = {
    # Vector table signatures (Initial SP should be in SRAM range)
    'sram_base': 0x20000000,   # SRAM typically starts here
    'sram_mask': 0xFF000000,   # Mask for SRAM detection
    'flash_base': 0x08000000,  # Flash typically starts here (STM32)
    'flash_alt': 0x00000000,   # Some devices map flash at 0
}


class ArmCortexDetector:
    """Detect ARM Cortex-M architecture binaries."""
    
    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.data = b''
        self.confidence = 0.0
        self.indicators: List[str] = []
        self.variant = "Unknown"  # M0, M3, M4, etc.
        
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
        """Check file extension for ARM-related formats."""
        arm_extensions = {
            '.bin': 0.1,      # Generic binary
            '.elf': 0.2,      # Could be ARM ELF
            '.hex': 0.15,     # Intel HEX (common for ARM)
            '.axf': 0.4,      # ARM Executable Format
            '.out': 0.15,     # GCC output
        }
        ext = self.filepath.suffix.lower()
        if ext in arm_extensions:
            self.indicators.append(f"File extension: {ext}")
            return arm_extensions[ext]
        return 0.0
    
    def check_elf_arm(self) -> float:
        """Check if file is ARM ELF format."""
        if len(self.data) < 52:
            return 0.0
            
        # ELF magic
        if self.data[:4] != b'\x7fELF':
            return 0.0
            
        # e_machine at offset 18 (16-bit value)
        e_machine = struct.unpack('<H', self.data[18:20])[0]
        
        # ARM = 40 (0x28)
        if e_machine == 40:
            # Check ELF flags for Cortex-M (EABI)
            # e_flags at offset 36 for 32-bit ELF
            if len(self.data) >= 40:
                e_flags = struct.unpack('<I', self.data[36:40])[0]
                
                # ARM EABI version in bits 24-31
                eabi_version = (e_flags >> 24) & 0xFF
                
                if eabi_version == 5:  # EABI5 = modern ARM toolchain
                    self.indicators.append("ELF ARM e_machine=40 (EABI5)")
                    return 0.7
                else:
                    self.indicators.append(f"ELF ARM e_machine=40 (flags={hex(e_flags)})")
                    return 0.6
            
            self.indicators.append("ELF ARM e_machine=40")
            return 0.5
            
        return 0.0
    
    def check_vector_table(self) -> float:
        """Check for Cortex-M vector table at start of file."""
        if len(self.data) < 8:
            return 0.0
            
        score = 0.0
        
        # Cortex-M vector table format:
        # Offset 0: Initial Stack Pointer (should point to end of SRAM)
        # Offset 4: Reset Handler address (entry point, must be odd for Thumb)
        
        try:
            initial_sp = struct.unpack('<I', self.data[0:4])[0]
            reset_handler = struct.unpack('<I', self.data[4:8])[0]
            
            # Check if Initial SP is in SRAM range (0x20000000 - 0x3FFFFFFF)
            sp_in_sram = (initial_sp & 0xE0000000) == 0x20000000
            
            # Reset handler should be odd (Thumb mode) and in reasonable range
            reset_is_thumb = (reset_handler & 0x1) == 1
            reset_reasonable = reset_handler > 0 and reset_handler < 0x20000000
            
            if sp_in_sram and reset_is_thumb:
                self.indicators.append(f"Vector table: SP=0x{initial_sp:08X}, Reset=0x{reset_handler:08X}")
                score = 0.4
                
                # Check more vectors (NMI, HardFault, etc.)
                if len(self.data) >= 16:
                    nmi_handler = struct.unpack('<I', self.data[8:12])[0]
                    hardfault = struct.unpack('<I', self.data[12:16])[0]
                    
                    # These should also be odd (Thumb) and in code region
                    nmi_valid = (nmi_handler & 0x1) == 1 and nmi_handler < 0x20000000
                    hf_valid = (hardfault & 0x1) == 1 and hardfault < 0x20000000
                    
                    if nmi_valid and hf_valid:
                        self.indicators.append("Valid NMI and HardFault vectors")
                        score = 0.5
                        
            elif sp_in_sram:
                # SP looks valid but reset handler not Thumb
                self.indicators.append(f"Possible vector table: SP=0x{initial_sp:08X}")
                score = 0.2
                
        except Exception:
            pass
            
        return score
    
    def analyze_thumb_instructions(self) -> float:
        """Analyze frequency of Thumb instruction patterns."""
        if len(self.data) < 32:
            return 0.0
            
        # Sample first 8KB for instruction analysis
        sample = self.data[:8192]
        
        push_lr_count = 0      # PUSH {.., LR}
        pop_pc_count = 0       # POP {.., PC}
        bl_count = 0           # BL (branch link)
        ldr_pc_count = 0       # LDR Rx, [PC, #imm]
        cond_branch_count = 0  # Conditional branches
        
        i = 0
        while i < len(sample) - 1:
            # Read 16-bit halfword (little-endian)
            hw = struct.unpack('<H', sample[i:i+2])[0]
            high_byte = (hw >> 8) & 0xFF
            low_byte = hw & 0xFF
            
            # Check for PUSH {.., LR}: 0xB5xx
            if high_byte == 0xB5:
                push_lr_count += 1
                i += 2
                continue
                
            # Check for POP {.., PC}: 0xBDxx
            if high_byte == 0xBD:
                pop_pc_count += 1
                i += 2
                continue
            
            # Check for BL (32-bit): 0xF0xx 0xF8xx or 0xF7xx 0xFFxx
            if high_byte in [0xF0, 0xF7] and i + 3 < len(sample):
                next_hw = struct.unpack('<H', sample[i+2:i+4])[0]
                next_high = (next_hw >> 8) & 0xFF
                if next_high >= 0xD0:  # BL continuation
                    bl_count += 1
                    i += 4
                    continue
            
            # Check for LDR Rx, [PC, #imm]: 0x48xx-0x4Fxx
            if 0x48 <= high_byte <= 0x4F:
                ldr_pc_count += 1
                i += 2
                continue
            
            # Check for conditional branches: 0xD0xx-0xDFxx
            if 0xD0 <= high_byte <= 0xDF:
                cond_branch_count += 1
                i += 2
                continue
            
            i += 2
        
        # Calculate score based on instruction frequencies
        score = 0.0
        total_instructions = len(sample) // 2
        
        # PUSH {LR} / POP {PC} pairs are very characteristic
        if push_lr_count >= 3 and pop_pc_count >= 3:
            self.indicators.append(f"PUSH{{LR}} found: {push_lr_count}, POP{{PC}} found: {pop_pc_count}")
            score += 0.3
            
        if bl_count >= 5:
            self.indicators.append(f"BL (function calls) found: {bl_count}")
            score += 0.15
            
        if ldr_pc_count >= 5:
            self.indicators.append(f"LDR [PC] (literal pools) found: {ldr_pc_count}")
            score += 0.1
            
        if cond_branch_count >= 3:
            self.indicators.append(f"Conditional branches found: {cond_branch_count}")
            score += 0.1
        
        # Check for function prologue/epilogue ratio
        if push_lr_count > 0 and pop_pc_count > 0:
            ratio = min(push_lr_count, pop_pc_count) / max(push_lr_count, pop_pc_count)
            if ratio > 0.5:
                self.indicators.append(f"Balanced prologue/epilogue ratio: {ratio:.2f}")
                score += 0.1
        
        return min(0.6, score)
    
    def check_cortex_m_specific(self) -> float:
        """Check for Cortex-M specific patterns."""
        if len(self.data) < 64:
            return 0.0
            
        score = 0.0
        
        # Check for SVC (supervisor call) instruction: 0xDFxx
        svc_count = 0
        for i in range(0, min(len(self.data), 4096) - 1, 2):
            if self.data[i+1] == 0xDF:
                svc_count += 1
        
        if svc_count >= 1:
            self.indicators.append(f"SVC instructions found: {svc_count}")
            score += 0.05
        
        # Check for CPSID/CPSIE (interrupt disable/enable)
        # These are Cortex-M specific
        for i in range(0, min(len(self.data), 4096) - 3, 2):
            if self.data[i:i+2] == b'\x72\xB6':  # CPSID i
                self.indicators.append("CPSID (disable interrupts) found")
                score += 0.1
                break
            if self.data[i:i+2] == b'\x62\xB6':  # CPSIE i
                self.indicators.append("CPSIE (enable interrupts) found")
                score += 0.1
                break
        
        # Check for MSR/MRS (system register access)
        msr_count = 0
        for i in range(0, min(len(self.data), 4096) - 3, 2):
            hw = struct.unpack('<H', self.data[i:i+2])[0]
            high = (hw >> 8) & 0xFF
            if high == 0xF3:  # MSR/MRS prefix
                msr_count += 1
        
        if msr_count >= 2:
            self.indicators.append(f"MSR/MRS (system reg) instructions: {msr_count}")
            score += 0.1
            
        return score
    
    def detect_variant(self) -> str:
        """Try to determine specific Cortex-M variant."""
        # This is heuristic-based
        
        # Check for floating point instructions (Cortex-M4F)
        has_fpu = False
        for i in range(0, min(len(self.data), 4096) - 3, 2):
            hw = struct.unpack('<H', self.data[i:i+2])[0]
            high = (hw >> 8) & 0xFF
            # VFP/FPU instructions start with 0xED or 0xEE
            if high in [0xED, 0xEE]:
                has_fpu = True
                break
        
        if has_fpu:
            self.variant = "Cortex-M4F"
            self.indicators.append("Floating point instructions detected (M4F)")
        else:
            # Could be M0, M3, or M4 without FPU
            # Check for Thumb-2 exclusive instructions
            has_thumb2 = False
            for i in range(0, min(len(self.data), 4096) - 3, 2):
                hw = struct.unpack('<H', self.data[i:i+2])[0]
                high = (hw >> 8) & 0xFF
                # Thumb-2 32-bit instruction prefixes
                if high in [0xE8, 0xE9, 0xEA, 0xEB]:
                    has_thumb2 = True
                    break
            
            if has_thumb2:
                self.variant = "Cortex-M3/M4"
            else:
                self.variant = "Cortex-M0/M0+"
        
        return self.variant
    
    def check_not_other_arm(self) -> float:
        """Check if this is likely NOT another ARM variant (A-series, R-series)."""
        if len(self.data) < 32:
            return 0.0
            
        # ARM A-series characteristics to reject:
        # - ARM mode (32-bit) instructions prevalent
        # - Different vector table format
        # - Different memory map
        
        arm32_count = 0
        
        # Check for ARM32 instruction patterns
        # ARM32 instructions are always word-aligned and have specific patterns
        for i in range(0, min(len(self.data), 4096) - 3, 4):
            word = struct.unpack('<I', self.data[i:i+4])[0]
            
            # ARM32 conditional field (bits 28-31)
            cond = (word >> 28) & 0xF
            
            # ARM32 instructions usually have condition != 0xF
            if cond != 0xF:
                # Check for ARM32 branch (0x0Axxxxxx or 0x0Bxxxxxx)
                if (word & 0x0F000000) in [0x0A000000, 0x0B000000]:
                    arm32_count += 1
        
        # If significant ARM32 instructions, this might be A-series, not M-series
        if arm32_count > 20:
            self.indicators.append(f"ARM32 instructions detected ({arm32_count}) - may be A-series")
            return -0.3
            
        return 0.0
    
    def check_not_xtensa(self) -> float:
        """Check if this is likely Xtensa/ESP32 (NOT ARM)."""
        if len(self.data) < 16:
            return 0.0
            
        score = 0.0
        
        # Check for ESP magic (0xE9 at byte 0)
        if self.data[0] == 0xE9:
            self.indicators.append("ESP magic (0xE9) detected - likely Xtensa, not ARM")
            return -0.5  # Strong negative
        
        # Check for Xtensa ENTRY instruction patterns (0x36)
        entry_count = 0
        for i in range(min(256, len(self.data) - 2)):
            if (self.data[i] & 0x0F) == 0x06 and (self.data[i] >> 4) == 0x03:
                entry_count += 1
        
        if entry_count >= 3:
            self.indicators.append(f"Xtensa ENTRY patterns found ({entry_count}) - likely Xtensa")
            score = -0.3
        
        return score
    
    def check_consistency(self) -> float:
        """Check for consistency - require multiple ARM indicators."""
        # If we only have vector table but no Thumb instructions, be skeptical
        has_vector_table = any('Vector table' in ind for ind in self.indicators)
        has_thumb = any('PUSH' in ind or 'POP' in ind or 'BL' in ind for ind in self.indicators)
        
        if has_vector_table and not has_thumb:
            # Vector table alone is not enough
            self.indicators.append("Vector table without Thumb patterns - reducing confidence")
            return -0.2
        
        return 0.0
    
    def detect(self) -> Dict:
        """Run full detection pipeline."""
        if not self.load_file():
            return {
                'is_arm_cortex': False,
                'confidence': 0.0,
                'error': 'Failed to load file',
                'architecture': 'Unknown'
            }
        
        # Run all detection methods
        scores = [
            self.check_file_extension(),
            self.check_elf_arm(),
            self.check_vector_table(),
            self.analyze_thumb_instructions(),
            self.check_cortex_m_specific(),
            self.check_not_other_arm(),
            self.check_not_xtensa(),
        ]
        
        # Add consistency check after collecting indicators
        scores.append(self.check_consistency())
        
        # Calculate total confidence
        self.confidence = sum(scores)
        self.confidence = max(0.0, min(1.0, self.confidence))
        
        # Detect variant
        if self.confidence >= 0.3:
            self.detect_variant()
        
        is_arm_cortex = self.confidence >= 0.5
        
        return {
            'is_arm_cortex': is_arm_cortex,
            'confidence': round(self.confidence, 2),
            'architecture': 'ARM',
            'variant': self.variant if is_arm_cortex else 'Unknown',
            'bits': 32,
            'endianness': 'little',
            'indicators': self.indicators,
            'file_size': len(self.data)
        }


def detect_arm_cortex(filepath: str) -> Dict:
    """Convenience function for ARM Cortex-M detection."""
    detector = ArmCortexDetector(filepath)
    return detector.detect()


# =============================================================================
# CLI Interface
# =============================================================================

if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python check_arm_cortex.py <binary_file>")
        print("Detects ARM Cortex-M architecture in binary files.")
        sys.exit(1)
    
    filepath = sys.argv[1]
    result = detect_arm_cortex(filepath)
    
    print(json.dumps(result, indent=2))
    
    sys.exit(0 if result['is_arm_cortex'] else 1)
