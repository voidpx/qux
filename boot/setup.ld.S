#include "../include/kmap.h"
OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)
SECTIONS
{
	. = BOOT_LOAD;
	.multiboot2 : { *(.multiboot2) }
	.text		: { *(.text) }
	.data       : { *(.data, .rodata, .rodata.*) }
	_kernel_start = .;
	.kernel_64 : { *(.kernel_64) }
	_kernel_end = .;
	boot_pgd = BOOT_PGD;
	kernel_load = KERNEL_LOAD;
}
