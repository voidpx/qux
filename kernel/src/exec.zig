const gdt = @import("gdt.zig");
const std = @import("std");
const us = @import("userspace.zig");
const elf = std.elf;
const console = @import("console.zig");
const mem = @import("mem.zig");
const lock = @import("lock.zig");
const task = @import("task.zig");
const flags = @import("flags.zig");
const object = @import("object.zig");
const fs = @import("fs.zig");
const io = @import("io.zig");
const msr = @import("msr.zig");
const AT_NULL   = 0                 ;
const AT_IGNORE = 1                 ;
const AT_EXECFD = 2                 ;
const AT_PHDR   = 3                 ;
const AT_PHENT  = 4                 ;
const AT_PHNUM  = 5                 ;
const AT_PAGESZ = 6                 ;
const AT_BASE   = 7                 ;
const AT_FLAGS  = 8                 ;
const AT_ENTRY  = 9                 ;
const AT_NOTELF = 10                ;
const AT_UID    = 11                ;
const AT_EUID   = 12                ;
const AT_GID    = 13                ;
const AT_EGID   = 14                ;
const AT_PLATFORM = 15              ;
const AT_HWCAP  = 16                ;
const AT_CLKTCK = 17                ;
const AT_SECURE = 23                ;
const AT_BASE_PLATFORM = 24         ;
const AT_RANDOM = 25	            ;
const AT_HWCAP2 = 26	            ;
const AT_RSEQ_FEATURE_SIZE	= 27;
const AT_RSEQ_ALIGN		= 28;
const AT_HWCAP3 = 29;
const AT_HWCAP4 = 30;
const AT_EXECFN = 31;

const syscall = @import("syscall.zig");

pub fn init() void {
    syscall.registerSysCall(syscall.SysCallNo.sys_execve, &sysExecve);
}

pub export fn sysExecve(file: [*:0]const u8, argv:?[*:null]?[*:0]const u8,
    envp:?[*:null]?[*:0]const u8) callconv(std.builtin.CallingConvention.SysV) i64 {
    if (exec(file, argv, envp)) |_| {
        return 0;
    } else |_| {
        return -1;
    }

}
pub fn exec(file: [*:0]const u8, argv:?[*:null]?[*:0]const u8, envp:?[*:null]?[*:0]const u8) !void {
    const l = lock.cli();
    defer lock.sti(l);
    var st:fs.Stat = undefined;
    if (fs.sysStat(file, &st) == -1) {
        return error.ErrorStatFile;
    }
    const f = fs.sysOpen(file, 0, 0);
    if (f == -1) return error.ErrorOpeningFile;
    defer _=fs.sysClose(f);
    
    const buffer = try mem.allocator.alloc(u8, @intCast(st.st_size));
    defer mem.allocator.free(buffer);

    if (fs.sysRead(@intCast(f), buffer.ptr, buffer.len) != buffer.len) {
        return io.IOError.ReadError; 
    }
    
    //const us_start:u64 = @intFromPtr(&us._start_us);
    //const us_end:u64 = @intFromPtr(&us._end_us);
    const hdr = elf.Header.parse(@alignCast(@ptrCast(buffer.ptr))) catch return error.NotExecutable;
    //const buf:[*]const u8 = @ptrFromInt(us_start);
    //const len = us_end - us_start;
    const source = std.io.StreamSource{.const_buffer = std.io.FixedBufferStream([]const u8){.buffer = buffer, .pos = 0}};
    var pit = hdr.program_header_iterator(source);
    const new_pgd =  mem.newPGD() catch return error.OutOfMemory;
    const mm = task.Mem.get_new() catch unreachable; 
    mm.pgd = new_pgd; 

    // the point of no return
    var cur = task.getCurrentTask();
    var oldmm = cur.mem;
    cur.mem = mm;
    mem.loadCR3(@intFromPtr(mm.pgd));
    oldmm.put();
    var phdr:u64 = undefined;
    while (pit.next() catch unreachable) |n| {
        console.print("phdr type: {}, addr: 0x{x}, memsz: 0x{x}\n", .{n.p_type, n.p_vaddr, n.p_memsz}); 
        if (n.p_type == elf.PT_LOAD) {
            _ = mm.mmap(n.p_vaddr, n.p_memsz, task.Mem.MAP_NOFT) catch |err| {
                console.print("unable to map elf: {}\n", .{err});
                task.taskExit(cur, 1);
            };
            var load_at:[*]u8 = @ptrFromInt(n.p_vaddr);
            @memcpy(load_at[0..n.p_filesz], buffer[n.p_offset..n.p_offset + n.p_filesz]);
            const brk = n.p_vaddr + n.p_memsz;
            if (n.p_offset <= hdr.phoff and hdr.phoff < n.p_offset + n.p_filesz) {
                phdr = n.p_vaddr + hdr.phoff - n.p_offset;
            }

            if (brk > mm.brk) mm.brk = brk;
        }
        if (n.p_type == elf.PT_TLS) {
            mm.fsbase = n.p_vaddr;
            msr.wrmsr(msr.MSR_FS_BASE, n.p_vaddr);
        }
    }
    var rsp = mem.user_max;
    rsp -= mem.page_size;
    // arg & env page
    _ = try mm.mmap(rsp, mem.page_size, task.Mem.MAP_NOFT);
    const argpage:[*]u8 = @ptrFromInt(rsp);
    _ = try mm.mmap(rsp - 10 * mem.page_size, 10 * mem.page_size, task.Mem.MAP_NOFT);
    
    const temp = try mem.allocator.alloc(u64, mem.page_size/@sizeOf(u64)); // TODO: handle the error, do proper cleanup
    defer mem.allocator.free(temp);
    var argc:u64 = 0;
    var vp:[*]u8 = argpage;
    if (argv) |aa| {
        while (true) : (argc += 1) {
            if (aa[argc]) |a| {
                const alen = std.mem.len(a) + 1; // 0 terminated
                @memcpy(vp, a[0..alen]); 
                temp[argc] = @intFromPtr(vp);
                vp += alen;
                vp = @ptrFromInt(((@as(u64, @intFromPtr(vp)) + 15) & ~@as(u64, 15)));
            } else { 
                break;
            }
        }
    }
    var envpc:u64 = 0;
    if (envp) |aa| {
        while (true) : (envpc += 1) {
            if (aa[envpc]) |a| {
                const alen = std.mem.len(a) + 1; // 0 terminated
                @memcpy(vp, a[0..alen]); 
                temp[argc + envpc] = @intFromPtr(vp);
                vp += alen;
            } else { 
                break;
            }
        }
    }
    const stack_alloc = 3 + 2 * 26 + 1; //
    rsp -= (argc + envpc + stack_alloc) * @sizeOf(u64);
    var tempp:[*]u64 = @ptrFromInt(rsp);
    tempp[stack_alloc - 1] = 0xabcdefab; // random
    const random_addr:u64 = @intFromPtr(&tempp[stack_alloc - 1]);
    tempp[0] = argc;
    tempp += 1;
    @memcpy(@as([*]u64, @ptrCast(tempp)), temp[0..argc]);
    tempp += argc;
    tempp[0] = 0;
    tempp += 1;
    @memcpy(@as([*]u64, @ptrCast(tempp)), temp[argc..argc+envpc]);
    tempp += envpc;
    tempp[0] = 0; // end of env
    tempp += 1;
    // begin of AUX vec
    tempp = addAUXEntry(tempp, AT_PHDR, phdr);
    tempp = addAUXEntry(tempp, AT_PHNUM, hdr.phnum);
    tempp = addAUXEntry(tempp, AT_PHENT, @sizeOf(elf.Phdr));
    tempp = addAUXEntry(tempp, AT_RANDOM, random_addr);
    tempp = addAUXEntry(tempp, AT_NULL, AT_NULL);

    var is = task.getCurrentState();
    //task.tss.sp0 = task.getCurrentSP0(); 
    is.cs = gdt.ucs;
    is.rip = hdr.entry;
    is.ss = gdt.uds;
    is.rsp = rsp; 
    //asm volatile(
    //    \\ movw %eax, %ds
    //    \\ movw %eax, %es
    //    :
    //    : [ds] "{eax}" (gdt.uds)

    //);
    is.rflags = flags.enumBitOr(.{flags.X86Flags.X86_EFLAGS_IF_BIT});
}

fn addAUXEntry(at:[*]u64, id:u64, v:u64) [*]u64 {
    at[0] = id;
    at[1] = v;
    return at + 2;
}

