"""
String-based architecture detector.
Searches binary content for architecture-identifying strings like 'riscv64', 'aarch64', 'mipsel', etc.
Very reliable for binaries containing compiler/toolchain metadata.
"""
from typing import List, Optional
from .base import BaseDetector, ArchDetectionResult


class StringDetector(BaseDetector):
    """
    Detect architecture from embedded strings in binary.
    
    Method: Search for architecture-identifying patterns in binary content.
    This works well for binaries with embedded paths, build info, or debug strings.
    """
    
    name = "string"
    weight = 2.5  # High weight - string evidence is very reliable
    
    # Architecture patterns with specificity order (more specific first)
    ARCH_PATTERNS = {
        # RISC-V (most specific patterns first)
        'RISCV64': [b'riscv64', b'rv64', b'RISCV64', b'riscv64-linux', b'riscv64-unknown'],
        'RISCV32': [b'riscv32', b'rv32', b'RISCV32', b'riscv32-linux'],
        
        # ARM64/AArch64
        'ARM64': [b'aarch64', b'arm64-', b'armv8', b'aarch64-linux', b'arm64-v8a'],
        
        # ARM32 (32-bit)
        'ARM32': [b'arm-linux', b'armv7', b'armhf', b'armel', b'arm-none-eabi', b'armv6'],
        'ARM-Thumb': [b'thumb', b'cortex-m', b'armv7-m'],
        
        # MIPS
        'MIPS-BE': [b'mips-linux', b'mips32', b'mipsbe', b'mips-'],
        'MIPS-LE': [b'mipsel', b'mips64el', b'mipsle'],
        
        # x86/x64
        'x86-64': [b'x86_64', b'x86-64', b'amd64', b'x86_64-linux'],
        'x86': [b'i386', b'i686', b'x86-linux', b'i486', b'i586'],
        
        # PowerPC
        'PowerPC': [b'powerpc', b'ppc64', b'ppc-', b'powerpc-linux'],
        
        # Others
        'Xtensa': [b'xtensa', b'esp32', b'esp8266'],
        'AVR': [b'avr-', b'atmega', b'attiny'],
    }
    
    # Minimum sample size for search
    SAMPLE_SIZE = 1024 * 1024  # 1MB max to search
    
    def is_available(self) -> bool:
        return True  # Always available
    
    def detect(self, data: bytes, offsets: List[int] = None) -> List[ArchDetectionResult]:
        """Search for architecture strings in binary content."""
        results = []
        
        # Use only portion of data for efficiency
        search_data = data[:self.SAMPLE_SIZE]
        search_lower = search_data.lower()
        
        # Count matches for each architecture
        arch_counts = {}
        arch_contexts = {}
        
        for arch, patterns in self.ARCH_PATTERNS.items():
            total_count = 0
            for pattern in patterns:
                count = search_lower.count(pattern.lower())
                if count > 0:
                    total_count += count
                    # Store first match context if not already stored
                    if arch not in arch_contexts:
                        idx = search_lower.find(pattern.lower())
                        if idx >= 0:
                            context = search_data[max(0, idx-5):idx+len(pattern)+30]
                            arch_contexts[arch] = context.decode('utf-8', errors='replace')
            
            if total_count > 0:
                arch_counts[arch] = total_count
        
        if not arch_counts:
            return []
        
        # Create results sorted by count
        for arch, count in sorted(arch_counts.items(), key=lambda x: -x[1]):
            # Confidence based on match count
            if count >= 20:
                confidence = 0.95
            elif count >= 10:
                confidence = 0.85
            elif count >= 5:
                confidence = 0.75
            elif count >= 2:
                confidence = 0.60
            else:
                confidence = 0.50
            
            # Determine bits and endian
            bits = 64 if '64' in arch else 32
            if arch in ['RISCV32', 'RISCV64']:
                endian = 'LE'
            elif 'BE' in arch:
                endian = 'BE'
            else:
                endian = 'LE'
            
            results.append(ArchDetectionResult(
                architecture=arch,
                confidence=confidence,
                offset=0,
                bits=bits,
                endian=endian,
                method=self.name,
                details={
                    "string_matches": count,
                    "context": arch_contexts.get(arch, ""),
                    "note": "Detected from embedded strings in binary"
                }
            ))
        
        return results


# Convenience function
def detect_with_strings(data: bytes) -> Optional[ArchDetectionResult]:
    """Quick detection using string search."""
    detector = StringDetector()
    results = detector.detect(data)
    return results[0] if results else None
