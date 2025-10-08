comptime {
    asm (
    \\
    \\.macro save_regs scret=0
    \\ push %rdi 
    \\ push %rsi
    \\ push %rdx
    \\ push %rcx
    \\ push %rax
    \\ push %r8
    \\ push %r9
    \\ push %r10
    \\ push %r11
    \\ push %rbx
    \\ push %rbp
    \\ push %r12
    \\ push %r13
    \\ push %r14
    \\ push %r15
    \\.if \scret == 1
    \\ push %rax
    \\.else
    \\ pushq $-1 // -1 if not from interrupt
    \\.endif
    \\.endm
    \\
    \\.macro restore_regs 
    \\ add $8, %rsp // sysno
    \\ pop %r15
    \\ pop %r14
    \\ pop %r13
    \\ pop %r12
    \\ pop %rbp
    \\ pop %rbx
    \\ pop %r11
    \\ pop %r10
    \\ pop %r9
    \\ pop %r8
    \\ pop %rax
    \\ pop %rcx
    \\ pop %rdx
    \\ pop %rsi
    \\ pop %rdi 
    \\.endm
    \\
    \\// make sure stack is 16 byte aligned
    \\.macro align_stack_call func:req, reg=%r12
    \\ mov %rsp, \reg
    \\ push %rsp
    \\ test $0xf, \reg
    \\ jnz 1f
    \\ push $0xaa 
    \\1:
    \\ sti
    \\ call \func
    \\ cli
    \\ pop \reg
    \\ cmp $0xaa, \reg 
    \\ jne 1f
    \\ pop \reg
    \\1:
    \\ mov \reg, %rsp // restore the stack after func call
    \\ sti
    \\.endm
    \\
    \\.macro entry_call_return exit_func:req
    \\ cli
    \\ mov %rsp, %rdi
    \\ call \exit_func
    \\ sti
    \\ cli
    \\restore_regs 
    \\ add $16, %rsp
    \\ iretq
    \\.endm
    \\
    \\.macro entry_call func:req, exit_func:req, scret=0 
    \\save_regs \scret
    \\ mov $0, %rbp // stop stack unwinding for interrupt handler?
    \\ mov %rsp, %rdi // *IntState
    \\ mov 128(%rsp), %rsi // vector, keep sync with IntState 
    \\ align_stack_call \func
    \\entry_call_return \exit_func 
    \\.endm
    \\
    );
}

pub fn init() void {
    // just to make sure asm above is included
}

