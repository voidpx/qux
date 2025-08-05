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
    .stat = undefined,
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
    closed:bool = false,
    fn ctor(p:*Pipe) !void {
        p.buf =  try std.RingBuffer.init(mem.allocator, mem.page_size);
        p.r_wq = .{};
        p.w_wq = .{};
    }
    fn new() !*Pipe {
        const p = try obj.new(Pipe, &ctor, &drop);
        return p;
    }

    fn close(p:*Pipe) void {
        p.closed = true;
        task.wakeup(&p.r_wq);
        task.wakeup(&p.w_wq);
    }

    fn drop(p:*Pipe) void {
        p.buf.deinit(mem.allocator);
    }
};

fn finalize(file:*fs.File) anyerror!void {
    const l = lock.cli();
    defer lock.sti(l);
    if (file.ctx == null) return;
    const p:*Pipe = @alignCast(@ptrCast(file.ctx));
    p.close();
    obj.put(p);
}

fn write(file:*fs.File, buf:[]const u8) anyerror!usize {
    const l = lock.cli();
    defer lock.sti(l);
    const p:*Pipe = @alignCast(@ptrCast(file.ctx));
    _=obj.get(p) orelse return error.InvalidPipe;
    defer obj.put(p);
    const rb:*std.RingBuffer = &p.buf;
    while (!p.closed and rb.isFull()) {
        const t = task.getCurrentTask();
        var wq = &p.w_wq;
        var node:task.WaitQueue.Node = .{.data = t};
        t.state = .blocked;
        wq.append(&node); 
        lock.sti(true);
        task.schedule();
        _=lock.cli();
    }
    if (!p.closed) {
        const len = rb.data.len - rb.len();
        const wl = @min(buf.len, len);
        const rl = buf.len - wl;
        try rb.writeSlice(buf[0..wl]);
        task.wakeup(&p.r_wq);
        return rl;
    }
    return error.ClosedPipe;
}

fn read(file:*fs.File, buf:[]u8) anyerror![]u8 {
    const l = lock.cli();
    defer lock.sti(l);
    const p:*Pipe = @alignCast(@ptrCast(file.ctx));
    _=obj.get(p) orelse return error.InvalidPipe;
    defer obj.put(p);
    const rb:*std.RingBuffer = &p.buf;
    while (!p.closed and rb.isEmpty()) {
        const t = task.getCurrentTask();
        var wq = &p.r_wq;
        var node:task.WaitQueue.Node = .{.data = t};
        t.state = .blocked;
        wq.append(&node); 
        lock.sti(true);
        task.schedule();
        _=lock.cli();
    }
    
    if (!p.closed) {
        const len = @min(buf.len, rb.len());
        try rb.readFirst(buf, len);
        task.wakeup(&p.w_wq);
        return buf[0..len];
    }
    return error.ClosedPipe;
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
    const wfd = t.fs.getFreeFd() catch return -1;
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
    wf.ctx = obj.get(pipe);
    pipe.rf = rf;
    pipe.wf = wf;
    t.fs.installFd(rfd, rf);
    t.fs.installFd(wfd, wf);
    fds[0] = @intCast(rfd);
    fds[1] = @intCast(wfd);
    _=&flags;
    return 0;
}

