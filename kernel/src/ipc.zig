const std = @import("std");
const syscall = @import("syscall.zig");
const fs = @import("fs.zig");
const mem = @import("mem.zig");
const lock = @import("lock.zig");
const task = @import("task.zig");
pub fn init() void {
    syscall.registerSysCall(syscall.SysCallNo.sys_pipe2, &sysPipe2);
}

const pipe_fops:fs.FileOps = .{
    .read = &read,
    .write = &write,
    .finalize = &finalize
};

const pipe_fs_ops:fs.FsOp = .{
    .stat = undefined,
    .lookup = undefined,
    .copy_path = undefined,
    .free_path = undefined
};

const obj = @import("object.zig");
const Pipe = struct {
    buf:std.RingBuffer,
    r_wq:task.WaitQueue,
    w_wq:task.WaitQueue,
    rf:?*fs.File,
    wf:?*fs.File,
    fn new() !*Pipe {
        const p = try mem.allocator.create(Pipe);
        p.buf =  std.RingBuffer.init(mem.allocator, mem.page_size) catch {
            mem.allocator.destroy(p);
            return error.OutOfMemory;
        }; 
        p.r_wq = .{};
        p.w_wq = .{};
        return p;
    }

    fn drop(p:*Pipe) void {
        p.buf.deinit(mem.allocator);
        mem.allocator.destroy(p);
    }
};

fn finalize(file:*fs.File) anyerror!void {
    const l = lock.cli();
    defer lock.sti(l);
    const p:*Pipe = @alignCast(@ptrCast(file.ctx));
    const rf = p.rf.?;
    const wf = p.wf.?;
    if (file == rf) {
        wf.put();
    } else if (file == wf) {
        rf.put();
    }
    p.drop();
}

fn write(file:*fs.File, buf:[]const u8) anyerror!usize {
    const l = lock.cli();
    defer lock.sti(l);
    const p:*Pipe = @alignCast(@ptrCast(file.ctx));
    const rb:*std.RingBuffer = &p.buf;
    while (rb.isFull()) {
        const t = task.getCurrentTask();
        var wq = &p.w_wq;
        var node:task.WaitQueue.Node = .{.data = t};
        t.state = .blocked;
        wq.append(&node); 
        lock.sti(true);
        task.schedule();
        _=lock.cli();
    }
    const len = rb.data.len - rb.len();
    const wl = @min(buf.len, len);
    const rl = buf.len - wl;
    try rb.writeSlice(buf[0..wl]);
    task.wake(&p.r_wq);
    return rl;
}

fn read(file:*fs.File, buf:[]u8) anyerror![]u8 {
    const l = lock.cli();
    defer lock.sti(l);
    const p:*Pipe = @alignCast(@ptrCast(file.ctx));
    const rb:*std.RingBuffer = &p.buf;
    while (rb.isEmpty()) {
        const t = task.getCurrentTask();
        var wq = &p.r_wq;
        var node:task.WaitQueue.Node = .{.data = t};
        t.state = .blocked;
        wq.append(&node); 
        lock.sti(true);
        task.schedule();
        _=lock.cli();
    }
    const len = @min(buf.len, rb.len());
    try rb.readFirst(buf, len);
    task.wake(&p.w_wq);
    return buf[0..len];
}

const pipe_fs:fs.MountedFs = .{
    .ctx = null,
    .ops = &pipe_fs_ops,
    .root = undefined,
    .fops = &pipe_fops
};

pub export fn sysPipe2(fds:*[2]u32, flags:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const rfd = t.fs.getFreeFd() catch return -1;
    const wfd = t.fs.getFreeFd() catch return -1;
    const pipe = Pipe.new() catch return -1;
    
    const rf = fs.File.get_new(fs.Path{.fs = undefined, .entry = undefined}, &pipe_fops) catch {
        pipe.drop();
        return -1;
    };
    rf.ctx = pipe;
    const wf = fs.File.get_new(fs.Path{.fs = undefined, .entry = undefined}, &pipe_fops) catch {
        pipe.drop();
        rf.put();
        return -1;
    };
    pipe.rf = rf;
    pipe.wf = wf;
    t.fs.installFd(rfd, rf);
    t.fs.installFd(wfd, wf);
    fds[0] = @intCast(rfd);
    fds[1] = @intCast(wfd);
    _=&flags;
    return 0;
}

