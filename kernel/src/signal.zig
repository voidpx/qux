pub const SigFrame = extern struct {
    ret_addr:u64,
    flags:u64,
    link:u64,
    ss_sp:u64,
    ss_flags:u32,
    ss_size:u64,
    context:SigContext,
    sig_info:extern struct {
        sig_no:i32,
        sig_errno:i32,
        sig_code:i32
    }
};

pub const TaskSignal = struct {
    sig:u64 = 0,
    mask_set:u64 = 0,
    sig_actions:[64]SigAction = .{SigAction{}}**64,

    pub fn signalOn(t:*@This(), s: Signal) bool {
        const bit = @as(u64, 1) << @truncate(@intFromEnum(s) - 1);
        if (t.mask_set & bit > 0) return false;
        return (t.sig & bit) > 0;
    }

    pub fn clearSignal(t:*@This(), s: Signal) void {
        t.sig &= ~(@as(u64, 1) << @truncate(@intFromEnum(s) - 1));
    }

    pub fn setSignal(t:*@This(), s:Signal) void {
        t.sig |= @as(u64, 1) << (@as(u6, @truncate(@intFromEnum(s))) - 1);
    }

    pub fn mask(t:*@This(), set:*u64, oset:?*u64) void {
        if (oset) |o| {
            o.* = t.mask_set;
        }
        t.mask_set |= set.*;
    }
    
    pub fn unmask(t:*@This(), set:*u64, oset:?*u64) void {
        if (oset) |o| {
            o.* = t.mask_set;
        }
        t.mask_set &= ~set.*;
    }
};

pub const SigContext = extern struct {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    di: u64,
    si: u64,
    bp: u64,
    bx: u64,
    dx: u64,
    ax: u64,
    cx: u64,
    sp: u64,
    ip: u64,
    flags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,

    fpstate: u64,
    reserved1: [8]u64,
};

pub const Signal = enum(u8) {
       hup   =       1,
       int    =       2,   
       quit   =       3,   
       ill    =       4,   
       trap   =       5,   
       abrt   =       6,   
       bus    =       7,   
       fpe    =       8,   
       kill   =       9,   
       usr1   =      10,   
       segv   =      11,   
       usr2   =      12,   
       pipe   =      13,   
       alrm   =      14,   
       term   =      15,   
       stkflt =      16,   
       chld   =      17,   
       cont   =      18,   
       stop   =      19,   
       tstp   =      20,   
       ttin   =      21,   
       ttou   =      22,   
       urg    =      23,   
       xcpu   =      24,   
       xfsz   =      25,   
       vtalrm =      26,   
       prof   =      27,   
       winch  =      28,   
       io     =      29,   
};
const std = @import("std");
const console = @import("console.zig");
pub export fn sysRtSigSuspend(sigset:?*anyopaque, sigsetsize:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&sigset;
    _=&sigsetsize;
    return 0;
}

pub const SigAction = struct {
    handler:?*const fn(u32) void = null,    
    flags:u64 = 0,
    restorer:?*const fn() void = null,
    sigset:u64 = 0
};

pub fn handleSignals(t:*task.Task) void {
    const fields = @typeInfo(Signal).@"enum".fields;
    inline for (fields) |f| {
        const s:Signal = @enumFromInt(f.value);
        if (t.signal.signalOn(s)) {
            t.signal.clearSignal(s);
            handleSignal(f.value);
            
        }
    }
}

fn handleSignal(s:i32) void {
    const t = task.getCurrentTask();
    const act = t.signal.sig_actions[@intCast(s)];
    const handler = act.handler orelse {
        if (t.id > 1) {
            task.taskExit(t, 1); 
        }
        return;
    };
    //console.print("handling signal {}, task:0x{x}\n", .{s, @as(u64, @intFromPtr(t))});
    const regs = task.getCurrentState();
    const fsp = std.mem.alignBackward(u64, regs.rsp - 128 - @sizeOf(SigFrame), 16);
    const sigframe:*SigFrame = @ptrFromInt(fsp);
    sigframe.flags = 0;
    sigframe.link = 0;
    sigframe.ss_sp = 0;
    sigframe.ss_size = 0;
    sigframe.ss_flags = 0;
    sigframe.context.flags = regs.rflags;
    sigframe.context.r8 = regs.r8;
    sigframe.context.r9 = regs.r9;
    sigframe.context.r10 = regs.r10;
    sigframe.context.r11 = regs.r11;
    sigframe.context.r12 = regs.r12;
    sigframe.context.r13 = regs.r13;
    sigframe.context.r14 = regs.r14;
    sigframe.context.r15 = regs.r15;
    sigframe.context.di = regs.rdi;
    sigframe.context.si = regs.rsi;
    sigframe.context.bp = regs.rbp;
    sigframe.context.bx = regs.rbx;
    sigframe.context.dx = regs.rdx;
    sigframe.context.ax = regs.rax;
    sigframe.context.cx = regs.rcx;
    sigframe.context.sp = regs.rsp;
    sigframe.context.ip = regs.rip;
    sigframe.context.cs = @intCast(regs.cs);
    sigframe.context.gs = 0;
    //sigframe.context.fs = @intCast(t.mem.fsbase);
    sigframe.context.ss = @intCast(regs.ss);
    sigframe.sig_info.sig_no = s;
    sigframe.sig_info.sig_errno = 0;
    sigframe.sig_info.sig_code = 0;
    if (act.restorer) |r| {
        sigframe.ret_addr = @intFromPtr(r);
    }
    
    regs.rsp = @intFromPtr(sigframe);
    regs.rip = @intFromPtr(handler);
    regs.rdi = @intCast(s);
    regs.rsi = @intFromPtr(&sigframe.sig_info);
    regs.rax = 0;
    regs.rdx = @intFromPtr(&sigframe.context);

}

pub export fn sysRtSigReturn() callconv(std.builtin.CallingConvention.SysV) i64 {
    //console.print("sigreturn\n", .{});
    const regs = task.getCurrentState();
    const sigframe:*SigFrame = @ptrFromInt(regs.rsp - @sizeOf(u64)); // count the ret_addr

    regs.rflags = sigframe.context.flags;
    regs.r8   =   sigframe.context.r8; 
    regs.r9   =   sigframe.context.r9; 
    regs.r10  =  sigframe.context.r10;
    regs.r11  =  sigframe.context.r11;
    regs.r12  =  sigframe.context.r12;
    regs.r13  =  sigframe.context.r13;
    regs.r14  =  sigframe.context.r14;
    regs.r15  =  sigframe.context.r15;
    regs.rdi  =   sigframe.context.di; 
    regs.rsi  =   sigframe.context.si; 
    regs.rbp  =   sigframe.context.bp; 
    regs.rbx  =   sigframe.context.bx; 
    regs.rdx  =   sigframe.context.dx; 
    regs.rax  =   sigframe.context.ax; 
    regs.rcx  =   sigframe.context.cx; 
    regs.rsp  =   sigframe.context.sp; 
    regs.rip  =   sigframe.context.ip; 
    regs.syscall_no = -1;

    return @intCast(regs.rax);
}

pub export fn sysRtSigAction(s:i32, act:?*SigAction, oact:?*SigAction, 
    sigsetsize:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    if (s < 0 or s >= 64) return -1;
    const action = act orelse return -1;
    const t = task.getCurrentTask();
    t.signal.sig_actions[@intCast(s)] = action.*;

    //console.print("sigaction: handler:{any}, sig:{}", .{act, s});
    _=&s; 
    _=&act;
    _=&oact;
    _=&sigsetsize;
    return 0;
}

const SIG_BLOCK = 0;
const SIG_UNBLOCK = 1;
const SIG_SETMASK = 2;
pub export fn sysRtSigProcMask(how:i32, set:*u64, oset:?*u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&how;
    _=&set;
    _=&oset;
    //console.print("sigprocmask: how:0x{x}, set:0x{x}, oset:0x{x}\n", .{how, 
    //    @as(u64, @intFromPtr(set)), @as(u64, @intFromPtr(oset))});
    const s = &task.getCurrentTask().signal;
    switch (how) {
        SIG_BLOCK => s.mask(set, oset),
        SIG_UNBLOCK => s.unmask(set, oset),
        SIG_SETMASK => s.mask_set = set.*,
        else => return -1
    } 
    return 0;
}
pub export fn sysRseq(addr:u64, len:u32, flags:i32, s:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&addr; // add this to Task
    _=&len;
    _=&flags;
    _=&s;
    console.print("rseq:0x{x}\n", .{addr});
    return 0;
}

pub export fn sysKill(pid:i32, s:i32) callconv(std.builtin.CallingConvention.SysV) i64 {
    if (task.getTask(@intCast(pid))) |t| { // TODO: handle signals
       task.taskExit(t, 0); 
    }
    // TODO: not implemented
    //taskExit(0);
    _=&pid;
    _=&s;
    return 0;
}

pub export fn sysTKill(tid:u32, s:i32) callconv(std.builtin.CallingConvention.SysV) i64 {
    task.taskExit(task.getTask(tid).?, 0);
    _=&tid;
    _=&s;
    return 0;
}
const task = @import("task.zig");
const syscall = @import("syscall.zig");
pub fn init() void {
    syscall.registerSysCall(syscall.SysCallNo.sys_rseq, &sysRseq);
    syscall.registerSysCall(syscall.SysCallNo.sys_rt_sigaction, &sysRtSigAction);
    syscall.registerSysCall(syscall.SysCallNo.sys_rt_sigreturn, &sysRtSigReturn);
    syscall.registerSysCall(syscall.SysCallNo.sys_rt_sigprocmask, &sysRtSigProcMask);
    syscall.registerSysCall(syscall.SysCallNo.sys_rt_sigsuspend, &sysRtSigSuspend);
    syscall.registerSysCall(syscall.SysCallNo.sys_tkill, &sysTKill);
    syscall.registerSysCall(syscall.SysCallNo.sys_kill, &sysKill);
}
