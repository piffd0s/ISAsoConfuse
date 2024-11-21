import struct
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def isasoconfuse(binary_path, output_path, avx512_code):
    """
    Inject AVX-512 instructions into the beginning of a binary.
    """
    try:
        # Read the original binary
        with open(binary_path, "rb") as f:
            original_binary = f.read()

        print(f"[+] Loaded binary: {binary_path} (Size: {len(original_binary)} bytes)")

        # Assemble AVX-512 instructions
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, _ = ks.asm(avx512_code)
        avx512_bytes = bytes(encoding)
        print(f"[+] Assembled AVX-512 code ({len(avx512_bytes)} bytes): {avx512_bytes.hex()}")

        # Create a new binary with AVX-512 instructions prepended
        patched_binary = avx512_bytes + original_binary

        # Write the patched binary
        with open(output_path, "wb") as f:
            f.write(patched_binary)

        print(f"[+] Patched binary saved to: {output_path}")

    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python isasoconfuse.py <input_binary> <output_binary>")
        return

    binary_path = sys.argv[1]
    output_path = sys.argv[2]

    # Example AVX-512 instructions
    # vaddpd zmm0, zmm1, zmm2 (vector add packed double-precision)
    avx512_code = """
        vaddpd zmm0, zmm1, zmm2
        vmovaps zmm3, zmm4
        ret
    """

    isasoconfuse(binary_path, output_path, avx512_code)

if __name__ == "__main__":
    main()
