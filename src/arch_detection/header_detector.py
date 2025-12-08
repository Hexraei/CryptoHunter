"""
Binary header analyzer for architecture detection.
Parses ELF, PE, and firmware headers to extract architecture info.
"""
import struct
from typing import List, Optional
from .base import BaseDetector, ArchDetectionResult


class HeaderDetector(BaseDetector):
    """
    Detect architecture by parsing binary headers (ELF, PE, firmware).
    
    Method: If a valid header is found, extract architecture directly.
    This is the most reliable method when headers are present.
    """
    
    name = "header"
    weight = 3.0  # Very high weight - headers are authoritative
    
    # ELF machine types
    ELF_MACHINES = {
        0x03: ("x86", 32, "LE"),
        0x08: ("MIPS-BE", 32, "BE"),  # Depends on endian flag
        0x14: ("PowerPC", 32, "BE"),
        0x15: ("PowerPC", 64, "BE"),
        0x28: ("ARM32", 32, "LE"),
        0x2B: ("SPARC", 64, "BE"),
        0x32: ("IA-64", 64, "LE"),
        0x3E: ("x86-64", 64, "LE"),
        0x5E: ("Xtensa", 32, "LE"),
        0xB7: ("ARM64", 64, "LE"),
        0xF3: ("RISCV32", 32, "LE"),  # Depends on class
    }
    
    # PE machine types
    PE_MACHINES = {
        0x014c: ("x86", 32, "LE"),
        0x0200: ("IA-64", 64, "LE"),
        0x8664: ("x86-64", 64, "LE"),
        0x01c0: ("ARM32", 32, "LE"),
        0x01c4: ("ARM-Thumb", 32, "LE"),
        0xaa64: ("ARM64", 64, "LE"),
    }
    
    def _parse_elf(self, data: bytes) -> Optional[ArchDetectionResult]:
        """Parse ELF header and extract architecture."""
        if len(data) < 52 or data[:4] != b'\x7fELF':
            return None
        
        # ELF class (32 or 64 bit)
        elf_class = data[4]
        bits = 64 if elf_class == 2 else 32
        
        # Endianness
        elf_data = data[5]
        endian = "BE" if elf_data == 2 else "LE"
        fmt = ">" if endian == "BE" else "<"
        
        # Machine type
        machine = struct.unpack(f"{fmt}H", data[18:20])[0]
        
        if machine in self.ELF_MACHINES:
            arch, default_bits, default_endian = self.ELF_MACHINES[machine]
            # Override with actual values from header
            return ArchDetectionResult(
                architecture=arch,
                confidence=0.99,  # Very high - from header
                offset=0,
                bits=bits,
                endian=endian,
                method=self.name,
                details={
                    "format": "ELF",
                    "machine": machine,
                    "class": elf_class
                }
            )
        else:
            return ArchDetectionResult(
                architecture=f"ELF-{machine}",
                confidence=0.80,
                offset=0,
                bits=bits,
                endian=endian,
                method=self.name,
                details={
                    "format": "ELF",
                    "machine": machine,
                    "unknown": True
                }
            )
    
    def _parse_pe(self, data: bytes) -> Optional[ArchDetectionResult]:
        """Parse PE header and extract architecture."""
        if len(data) < 64 or data[:2] != b'MZ':
            return None
        
        # PE header offset
        pe_offset = struct.unpack("<I", data[60:64])[0]
        
        if pe_offset + 6 > len(data):
            return None
        
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None
        
        # Machine type
        machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
        
        if machine in self.PE_MACHINES:
            arch, bits, endian = self.PE_MACHINES[machine]
            return ArchDetectionResult(
                architecture=arch,
                confidence=0.99,
                offset=0,
                bits=bits,
                endian=endian,
                method=self.name,
                details={
                    "format": "PE",
                    "machine": hex(machine)
                }
            )
        
        return None
    
    def _parse_arm_cortex_vector(self, data: bytes) -> Optional[ArchDetectionResult]:
        """Check for ARM Cortex-M vector table at offset 0."""
        if len(data) < 8:
            return None
        
        # ARM Cortex-M: SP at 0x0, Reset at 0x4
        sp = struct.unpack("<I", data[0:4])[0]
        reset = struct.unpack("<I", data[4:8])[0]
        
        # SP should be in SRAM range, Reset should be odd (Thumb) and in Flash
        if (0x20000000 <= sp <= 0x40000000 and 
            0x08000000 <= reset <= 0x10000000 and
            reset & 1 == 1):
            return ArchDetectionResult(
                architecture="ARM-Thumb",
                confidence=0.95,
                offset=0,
                bits=32,
                endian="LE",
                method=self.name,
                details={
                    "format": "ARM-Cortex-M-Vector",
                    "stack_pointer": hex(sp),
                    "reset_vector": hex(reset)
                }
            )
        
        return None
    
    def _find_embedded_elf(self, data: bytes) -> List[ArchDetectionResult]:
        """Search for ELF headers embedded within the binary."""
        results = []
        elf_magic = b'\x7fELF'
        
        idx = 0
        while True:
            pos = data.find(elf_magic, idx)
            if pos == -1 or pos > 500000:  # Limit search
                break
            
            # Try to parse ELF at this offset
            result = self._parse_elf(data[pos:])
            if result:
                result.offset = pos
                result.confidence *= 0.9  # Slightly lower for embedded
                result.details["embedded"] = True
                result.details["embed_offset"] = hex(pos)
                results.append(result)
            
            idx = pos + 1
        
        return results
    
    def detect(self, data: bytes, offsets: List[int] = None) -> List[ArchDetectionResult]:
        """Detect architecture from headers."""
        results = []
        
        # Try ELF at offset 0
        elf_result = self._parse_elf(data)
        if elf_result:
            results.append(elf_result)
        
        # Try PE at offset 0
        pe_result = self._parse_pe(data)
        if pe_result:
            results.append(pe_result)
        
        # Try ARM Cortex-M vector table
        cortex_result = self._parse_arm_cortex_vector(data)
        if cortex_result:
            results.append(cortex_result)
        
        # Search for embedded ELF if nothing found at start
        if not results:
            embedded = self._find_embedded_elf(data)
            results.extend(embedded[:3])  # Max 3 embedded headers
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
