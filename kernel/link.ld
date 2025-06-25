ENTRY(_qux_start)

KERNEL_BASE = 0xffff800000000000;
KERNEL_PHYADDR = 0x1000000;
KERNEL_STACK_SIZE = 0x2000;
SECTIONS {
    . = KERNEL_BASE + KERNEL_PHYADDR;
    _init_stack = . - KERNEL_STACK_SIZE;
    _init_stack_end = .; 
    _stext = .;
    .text : AT(. - KERNEL_BASE) {
        *(.text, .text.*)
    }
    _etext = .;
    _sdata = .;
    .rodata : AT(. - KERNEL_BASE) {
        *(.rodata, .rodata.*)
    }
    .data : AT(. - KERNEL_BASE) {
        *(.data, .data.*)
    }
    _edata = .;
    _sbss = .;
    .bss : AT(. - KERNEL_BASE) {
        *(.bss, .bss.*)
    }
    _ebss = .;
    /DISCARD/ : {*(.got)}
}

