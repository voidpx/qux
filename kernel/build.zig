const std = @import("std");

pub fn build(b: *std.Build) void {
    var disabled_features = std.Target.Cpu.Feature.Set.empty;
    var enabled_features = std.Target.Cpu.Feature.Set.empty;

    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.mmx));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse2));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx2));
    enabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.soft_float));
    
    const target_query = std.Target.Query{
        .cpu_arch = std.Target.Cpu.Arch.x86_64,
        .os_tag = std.Target.Os.Tag.freestanding,
        .abi = std.Target.Abi.none,
        .cpu_features_sub = disabled_features,
        .cpu_features_add = enabled_features,
    };
    const optimize = b.standardOptimizeOption(.{}); 
    const kernel = b.addExecutable(.{ 
        .name = "qux",
        .root_source_file = b.path("src/main.zig"),
        .target = b.resolveTargetQuery(target_query), 
        .optimize = optimize, 
        .linkage = .static,
        .pic = true , 
        .code_model = .kernel});
    kernel.root_module.red_zone = false;
    kernel.addIncludePath(b.path("../include"));
    kernel.addAssemblyFile(b.path("src/head.S"));
    kernel.entry = .{ .symbol_name = "_qux_start"};
    kernel.pie = false;
    kernel.setLinkerScript(b.path("link.ld"));

    //kernel.linkLibC(false);
    const install_kernel = b.addInstallArtifact(kernel, .{});
    //b.installArtifact(kernel);
    b.getInstallStep().dependOn(&install_kernel.step);

   // const boot = b.addSystemCommand(&.{"./build", "-S"});
   // boot.setCwd(b.path("../boot"));
   // b.getInstallStep().dependOn(&boot.step);
}
