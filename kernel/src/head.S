
.section ".text", "ax", @progbits
.global _qux_start
.type _qux_start, @function
_qux_start:
	xor %rbp, %rbp
	mov .Linit_sp(%rip), %rsp
	callq *.Lstart64(%rip) # go to high address

.Lstart64:
	.quad startKernel
	
.Linit_sp:
	.quad _init_stack_end

