#!/usr/bin/env python3
"""
Fast architecture detection using Capstone disassembler.
Tests multiple architectures and counts valid instruction ratio.
"""
from capstone import *
import os

# Architectures to test
ARCHS = [
    (CS_ARCH_ARM, CS_MODE_THUMB, "ARM Thumb"),
    (CS_ARCH_ARM, CS_MODE_ARM, "ARM 32-bit"),
    (CS_ARCH_ARM64, CS_MODE_ARM, "ARM64"),
    (CS_ARCH_X86, CS_MODE_32, "x86 32-bit"),
    (CS_ARCH_X86, CS_MODE_64, "x86-64"),
    (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN, "MIPS32 LE"),
    (CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN, "MIPS32 BE"),
]

def test_architecture(data, arch, mode, name):
    """Test if data disassembles well with given architecture."""
    try:
        md = Cs(arch, mode)
        md.skipdata = True
        
        # Disassemble first 50KB
        sample = data[:min(len(data), 50000)]
        
        valid = 0
        invalid = 0
        
        for insn in md.disasm(sample, 0x0):
            if insn.mnemonic:
                valid += 1
            else:
                invalid += 1
        
        total = valid + invalid
        ratio = valid / max(total, 1)
        
        return {
            'name': name,
            'valid': valid,
            'invalid': invalid,
            'ratio': ratio
        }
    except Exception as e:
        return {'name': name, 'error': str(e), 'ratio': 0}

def analyze_file(filepath):
    """Analyze a binary file with all architectures."""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"\n{'='*60}")
    print(f"FILE: {os.path.basename(filepath)}")
    print(f"SIZE: {len(data):,} bytes")
    print(f"{'='*60}")
    
    results = []
    for arch, mode, name in ARCHS:
        result = test_architecture(data, arch, mode, name)
        results.append(result)
        print(f"  {name:<15}: {result['valid']:>6} valid, ratio={result['ratio']:.1%}")
    
    # Find best match
    best = max(results, key=lambda x: x['ratio'])
    print(f"\n  >>> BEST MATCH: {best['name']} ({best['ratio']:.1%} valid)")
    
    return best

if __name__ == '__main__':
    print("CAPSTONE ARCHITECTURE DETECTION - Phase_2 Binaries")
    print("=" * 60)
    
    best_matches = {}
    for i in range(1, 9):
        filepath = f'Phase_2/P_2_S_{i}.bin'
        if os.path.exists(filepath):
            best = analyze_file(filepath)
            best_matches[filepath] = best['name']
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for f, arch in best_matches.items():
        print(f"  {os.path.basename(f)}: {arch}")
