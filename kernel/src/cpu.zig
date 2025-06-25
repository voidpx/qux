pub const Feature = enum(u8) {
    sse,
    sse2
//more
};

pub const FeatureErr = error {
    no_sse
};

pub const CpuId01 = struct {
    edx:u32,
    ecx:u32
};

pub fn cpuId01() CpuId01 {
    var ret = CpuId01{.edx = 0, .ecx = 0};
    asm volatile(
    \\movl $1, %eax
    \\cpuid
    \\movl %edx, (%rdi)
    \\movl %ecx, (%rsi)
    : : [edx] "{rdi}" (&ret.edx),
        [ecx] "{rsi}" (&ret.ecx)
    : "rax"
    );
    return ret;
}

pub fn enableSSE() FeatureErr!void {
    if (!hasFeature(Feature.sse)) {
        return FeatureErr.no_sse;
    }
    asm volatile(
    \\mov %cr0, %rax
    \\and $~4, %rax
    \\or  $2, %rax
    \\mov %rax, %cr0
    \\mov %cr4, %rax
    \\or $3<<9, %rax
    \\mov %rax, %cr4
    :::"rax"
    );
}

pub fn hasFeature(f:Feature) bool {
    const c = cpuId01();
    switch (f) {
        Feature.sse => return c.edx & (1<<25) > 0,
        else => return false
    }
}

