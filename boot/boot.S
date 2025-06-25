// multiboot2 header, bootstrap
#define MULTIBOOT2_HEADER_MAGIC 0xe85250d6
#define MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS  4
#define MULTIBOOT_HEADER_TAG_FRAMEBUFFER  5
#define MULTIBOOT_HEADER_TAG_OPTIONAL 1
#define MULTIBOOT_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED 2

/* setup stack. */
#define STACK_SIZE                      0x4000
        .section .multiboot2, "ax"

        .globl   _start, goto_long_mode
_start:
        jmp     multiboot_entry

        /* multiboot2 header align . */
        .align  8
        
multiboot_header:
        .long   MULTIBOOT2_HEADER_MAGIC
        .long   0
        .long   multiboot_header_end - multiboot_header
        /*  checksum */
        .long   -(MULTIBOOT2_HEADER_MAGIC + (multiboot_header_end - multiboot_header))
//console_flags_tag:
//        .short MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS    
//        .short MULTIBOOT_HEADER_TAG_OPTIONAL
//        .long 12        
//        .long MULTIBOOT_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED
//        .long 0  // align
framebuffer_tag_start:  
        .short MULTIBOOT_HEADER_TAG_FRAMEBUFFER
        .short MULTIBOOT_HEADER_TAG_OPTIONAL
        .long framebuffer_tag_end - framebuffer_tag_start
        .long 1024 
        .long 768
        .long 0
framebuffer_tag_end:
        .long 0   // align
        .short 0  // end with type 0
        .short 0
        .long 8
multiboot_header_end:
multiboot_entry:
        movl    $(stack + STACK_SIZE), %esp

        push   $0
        popf

        push   %ebx
        push   %eax

        // never return
        call    setup
        
loop:   hlt
        jmp     loop


goto_long_mode:
        leal	gdtr, %eax
	lgdt	(%eax)

        //XXX: check cpu before enabling sse 
        /* Enable PAE mode */
	movl	%cr4, %eax
	orl	$1<<5, %eax
        //orl     $1<<9, %eax // sse
        //orl     $1<<10, %eax // sse
	movl	%eax, %cr4

        leal	boot_pgd, %eax
	movl	%eax, %cr3

        /* Enable Long mode in EFER (Extended Feature Enable Register) */

#define MSR_EFER		0xc0000080
#define EFER_LME		8
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$EFER_LME, %eax
	wrmsr

	/* After gdt is loaded */
	xorl	%eax, %eax
	lldt	%ax
	movl    $24, %eax
	ltr	%eax

        movl    4(%esp), %eax // kernel start
        movl    12(%esp), %edi  // boot info

	pushl	$8
	pushl   %eax	

	/* Enter paged protected Mode, activating Long Mode */
//	movl	$0x80050033, %eax
//	movl	%eax, %cr0
        movl %cr0, %eax                // Set the A-register to control register 0.
        orl $0x80000001, %eax              // Set the PG-bit, which is the 32nd bit (bit 31), bit 1 for sse, bit 0 for protected mode
        //andl $~4, %eax // sse
        movl %eax, %cr0  

	/* Load segment registers with our descriptors */
	movl	$16, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss

	/* switch to 64bit mode. */
	lret
        

.comm   stack, STACK_SIZE

.section .kernel_64, "ax"
.incbin KERNEL_FILE 

