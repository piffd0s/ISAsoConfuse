# ISAsoConfuse
AVX-512 anti sandbox / ISA specific research for disobey conf

use the included tool to patch avx-512 instructions into an arbitrary binary thereby only allowing the binary to run on avx-512 supported systems. this will break a large number of sandboxes.

use the patcher to add avx-512 instructions to arbitrary binaries or use the porter to port x86 shellcode to avx-512 instructions where appropriate.
