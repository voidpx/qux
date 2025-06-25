
//* x86-64 specific MSRs */
pub const MSR_EFER		= 0xc0000080; //* extended feature register */
pub const MSR_STAR		= 0xc0000081;  //* legacy mode SYSCALL target */
pub const MSR_LSTAR		= 0xc0000082;  //* long mode SYSCALL target */
pub const MSR_CSTAR		= 0xc0000083;  //* compat mode SYSCALL target */
pub const MSR_SYSCALL_MASK	= 0xc0000084;  //* EFLAGS mask for syscall */
pub const MSR_FS_BASE		= 0xc0000100;  //* 64bit FS base */
pub const MSR_GS_BASE		= 0xc0000101;  //* 64bit GS base */
pub const MSR_KERNEL_GS_BASE	= 0xc0000102;  //* SwapGS GS shadow */
pub const MSR_TSC_AUX		= 0xc0000103;  //* Auxiliary TSC */
pub const EFERBitPos = enum(u8) {
//* EFER bits: */
 EFER_SCE	=	0  ,//* SYSCALL/SYSRET */
 EFER_LME	=	8  ,//* Long mode enable */
 EFER_LMA	=	10 ,//* Long mode active (read-only) */
 EFER_NX	=	11 ,//* No execute enable */
 EFER_SVME	=	12 ,//* Enable virtualization */
 EFER_LMSLE	=	13 ,//* Long Mode Segment Limit Enable */
 EFER_FFXSR	=	14 ,//* Enable Fast FXSAVE/FXRSTOR */
 EFER_AUTOIBRS=		21 //* Enable Automatic IBRS */
};

pub fn wrmsr(msr:u32, v:u64) void {
    asm volatile(
    "wrmsr"
    :
    : [msr] "{ecx}" (msr),
      [low] "{eax}" (@as(u32, @truncate(v))),
      [high] "{edx}" (@as(u32, @truncate(v >> 32)))
    );
}

pub fn rdmsr(msr:u32) u64 {
    const ret = 
    asm volatile(
    \\ rdmsr
    \\ shl %rdx
    \\ or %rdx, %rax
    \\
    : [ret] "={rax}" (->u64)
    : [msr] "{ecx}" (msr),
    );
    return ret;
}

