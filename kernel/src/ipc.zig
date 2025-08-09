const std = @import("std");
const syscall = @import("syscall.zig");
const fs = @import("fs.zig");
const mem = @import("mem.zig");
const lock = @import("lock.zig");
const task = @import("task.zig");
pub fn init() void {
    syscall.registerSysCall(syscall.SysCallNo.sys_pipe2, &sysPipe2);
    syscall.registerSysCall(syscall.SysCallNo.sys_pipe, &sysPipe);
}

const pipe_fops:fs.FileOps = .{
    .read = &read,
    .write = &write,
    .finalize = &finalize
};

const pipe_fs_ops:fs.FsOp = .{
    .stat = &stat,
    .lookup = undefined,
    .lookupAt = undefined,
    .copy_path = undefined,
    .free_path = &dummpyFreePath
};

fn dummpyFreePath(_:*fs.MountedFs, _:fs.Path) void {
}

const obj = @import("object.zig");
const Pipe = struct {
    buf:std.RingBuffer,
    r_wq:task.WaitQueue,
    w_wq:task.WaitQueue,
    rf:?*fs.File,
    wf:?*fs.File,
    rclosed:bool = false,
    wclosed:bool = false,
    fn ctor(p:*Pipe) !void {
        p.buf =  try std.RingBuffer.init(mem.allocator, mem.page_size);
        p.r_wq = .{};
        p.w_wq = .{};
    }
    fn new() !*Pipe {
        const p = try obj.new(Pipe, &ctor, &drop);
        return p;
    }

    fn closeWrite(p:*Pipe) void {
        p.wclosed = true;
        if (!p.rclosed) task.wakeup(&p.r_wq);
    }
    fn closeRead(p:*Pipe) void {
        p.rclosed = true;
        if (!p.wclosed) task.wakeup(&p.w_wq);
    }

    fn drop(p:*Pipe) void {
        p.buf.deinit(mem.allocator);
    }
};

fn getPipe(a:*anyopaque) struct {*Pipe, bool} {
    var pa:u64 = @intFromPtr(a);
    const isRead = (pa & 1) == 0;
    pa &= ~@as(u64, 1);
    const p:*Pipe = @ptrFromInt(pa);
    return .{p, isRead};
}

fn finalize(file:*fs.File) anyerror!void {
    const l = lock.cli();
    defer lock.sti(l);
    if (file.ctx == null) return;
    const r = getPipe(file.ctx.?);
    const p = r[0];
    const isRead = r[1];
    if (isRead) {
        p.closeRead();
    } else {
        p.closeWrite();
    }
    obj.put(p);
}

fn write(file:*fs.File, buf:[]const u8) anyerror!usize {
    const l = lock.cli();
    defer lock.sti(l);
    const r = getPipe(file.ctx.?);
    const p = r[0];
    _=obj.get(p) orelse return error.InvalidPipe;
    defer obj.put(p);
    const rb:*std.RingBuffer = &p.buf;
    while (!p.rclosed and rb.isFull()) {
        const t = task.getCurrentTask();
        var wq = &p.w_wq;
        var node:task.WaitQueue.Node = .{.data = t};
        t.state = .blocked;
        wq.append(&node); 
        task.scheduleWithIF();
    }
    if (!rb.isFull()) {
        const len = rb.data.len - rb.len();
        const wl = @min(buf.len, len);
        //const rl = buf.len - wl;
        try rb.writeSlice(buf[0..wl]);
        if (!p.rclosed) task.wakeup(&p.r_wq);
        return wl;
    }
    return 0;
}

fn stat(pfs:*fs.MountedFs, path:fs.Path, s:*fs.Stat) anyerror!i64 {
    _=&pfs;
    _=&path;
    s.st_mode = 0x1000;
    return 0;
}

fn read(file:*fs.File, buf:[]u8) anyerror![]u8 {
    const l = lock.cli();
    defer lock.sti(l);
    const r = getPipe(file.ctx.?);
    const p = r[0];
    _=obj.get(p) orelse return error.InvalidPipe;
    defer obj.put(p);
    const rb:*std.RingBuffer = &p.buf;
    while (!p.wclosed and rb.isEmpty()) {
        const t = task.getCurrentTask();
        var wq = &p.r_wq;
        var node:task.WaitQueue.Node = .{.data = t};
        t.state = .blocked;
        wq.append(&node); 
        task.scheduleWithIF();
    }
   
    if (!rb.isEmpty()) {
        const len = @min(buf.len, rb.len());
        try rb.readFirst(buf, len);
        if (!p.wclosed) task.wakeup(&p.w_wq);
        return buf[0..len];
    }
    return buf[0..0];
}

const pipe_fs:fs.MountedFs = .{
    .ctx = null,
    .ops = &pipe_fs_ops,
    .root = undefined,
    .fops = &pipe_fops
};

pub export fn sysPipe(fds:*[2]u32, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    return sysPipe2(fds, 0);
}

pub export fn sysPipe2(fds:*[2]u32, flags:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const rfd = t.fs.getFreeFd() catch return -1;
    const pipe = Pipe.new() catch return -1;
    
    const rf = fs.File.get_new(fs.Path{.fs = @constCast(&pipe_fs), .entry = undefined}, &pipe_fops) catch {
        obj.put(pipe);
        return -1;
    };
    rf.ctx = pipe;
    const wf = fs.File.get_new(fs.Path{.fs = @constCast(&pipe_fs), .entry = undefined}, &pipe_fops) catch {
        obj.put(pipe);
        rf.put();
        return -1;
    };
    const wp = obj.get(pipe) orelse return -1;
    const wpi:u64 = @intFromPtr(wp) + 1;
    wf.ctx = @ptrFromInt(wpi);
    pipe.rf = rf;
    pipe.wf = wf;
    t.fs.installFd(rfd, rf);
    const wfd = t.fs.getFreeFd() catch {
        _=fs.sysClose(@intCast(rfd));
        return -1;
    };
    t.fs.installFd(wfd, wf);
    fds[0] = @intCast(rfd);
    fds[1] = @intCast(wfd);
    _=&flags;
    return 0;
}

