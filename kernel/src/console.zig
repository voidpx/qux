const std = @import("std");
const mem = @import("mem.zig");
pub const Con = struct {
    ctx:?*anyopaque = null,
    write: *const fn(self:*@This(), char:u32) anyerror!void,
    cursor: *const fn(self:*@This(), on:bool) void,
    scroll_up: *const fn(self:*@This()) void,
    scroll_down: *const fn(self:*@This()) void

};

pub var con:?*Con = null;
const console_buf_len = 0x256;
var buffer = [_]u32{0} ** console_buf_len;
pub var console_buf = RingBuffer.new(buffer[0..]);
const input = @import("input.zig");
pub fn init() void {
    input.registerInputHandler(&consoleInputHandler);
}

const task = @import("task.zig");
var input_buf:InputBuffer = undefined;
var input_wq:task.WaitQueue = .{};

const input_buf_cap = 128;

pub var stdin:*fs.File = undefined;
pub var stdout:*fs.File = undefined;
pub var stderr:*fs.File = undefined;
// must be called after mem init
pub fn inputInit() void {
    input_buf = std.RingBuffer.init(mem.allocator, input_buf_cap) catch unreachable;
    const dummy_path = fs.Path{.fs = @constCast(&console_fs), .entry = undefined};
    stdin = fs.File.get_new(dummy_path, console_fs.fops) catch unreachable; 
    stdout = stdin;
    stderr = stdin;
}

pub fn registerConsole(c:*Con) void {
    con = c;
    for (0..console_buf.getSize()) |i| {
        c.write(c, console_buf.get(i)) catch unreachable;
    }
}

pub const LineControl = struct {
    new_line:*const fn(lb:*LineBuffer) anyerror!*Line,
};

pub const Line = struct {
    len:u32 = 0,
    scr_cursor:u32 = 0,
    index:i32 = 0, // index on screen, >=0 & < screen lines: visible
    line:[]u32,
    next:?*Line = null,
    prev:?*Line = null,
    pub fn add(self:*Line, char:u32) void {
        std.debug.assert(self.len < self.line.len);
        self.line[self.len] = char;
        self.len += 1;
    }
};

pub const LineBuffer = struct {
    first:?*Line = null,
    last:?*Line = null,
    lines:usize = 0,
    line_control:*const LineControl,
    const max_lines:usize = 1000;
    pub fn new(lc:*LineControl) LineBuffer {
        return .{.line_control = lc};
    }
    pub fn appendLine(self:*LineBuffer) !*Line {
        var line = try self.newLine();
        if (self.last == null) {
            self.first = line;
            self.last = line;
        } else {
            self.last.?.next = line;
            line.prev = self.last.?;
            self.last = line;
        }
        self.lines += 1;
        return line;
    }
    fn newLine(self:*LineBuffer) !*Line {
        var line:*Line = undefined;
        if (self.lines >= max_lines) {
            const reuse = self.first.?;
            self.first = reuse.next;
            self.first.?.prev = null;
            reuse.len = 0;
            reuse.scr_cursor = 0;
            reuse.index = 0;
            line = reuse;
        } else {
            line = try self.line_control.new_line(self);
        }
        line.prev = null;
        line.next = null;
        return line;
    }
};

const InputBuffer = std.RingBuffer;
// ring buffer that just overwrites the head when it's full.
const RingBuffer = struct {
    buf:[]u32,
    cursor:usize = 0,
    start:isize = 0,
    pub fn new(backing_buf:[]u32) RingBuffer {
        return .{.buf = backing_buf};
    }
    pub fn write(self:*@This(), char:u32) void {
        self.buf[self.cursor] = char;
        self.cursor = (self.cursor + 1) % self.buf.len;
        if (self.cursor == self.start) {
            self.start = -1; // full
        }
    }

    pub fn reset(self:*@This()) void {
        self.cursor = 0;
        self.start = 0;
    }

    pub fn getStartIdx(self:*@This()) usize {
        return if (self.start == -1) self.cursor else @intCast(self.start);
    }

    pub fn getSize(self:*@This()) usize {
        return if (self.start == -1) self.buf.len else self.cursor;
    }

    pub fn getEndIdx(self:*@This()) usize {
        return self.cursor;
    }

    pub fn get(self:*@This(), index:usize) u32 {
        std.debug.assert(index >= 0 and index < self.getSize());
        const idx = (self.getStartIdx() + index) % self.buf.len;
        return self.buf[idx];
    }

    pub fn iter(self:*@This()) RingBufferIter {
        return RingBufferIter.new(self);
    }

};

const RingBufferIter = struct {
    rb:*RingBuffer,
    index:usize = 0,
    fn new(ring_buf:*RingBuffer) RingBufferIter {
        return .{.rb = ring_buf};
    }
    pub fn next(self:*@This()) ?u32 {
        if (self.index >= self.rb.getSize()) return null;
        const r = self.rb.get(self.index);
        self.index += 1;
        return r;
    }
};

const console_err = error{ConsoleError};
pub const writer = std.io.Writer(void, console_err, consoleWrite){ .context = {} };
const lock = @import("lock.zig");
pub fn log(comptime template: []const u8, arg: anytype) void {
    const v = lock.cli();
    defer lock.sti(v);
    if (time_call) |f| {
        const t = f();
        const sec = t / time.nsec_per_sec;
        const msec = (t % time.nsec_per_sec)/time.nsec_per_milli_sec;
        _ = std.fmt.format(writer, "[{}.{d:0>6.6}] ", .{sec, msec}) catch unreachable;
    }
    print(template, arg);
}
pub fn print(comptime template: []const u8, arg: anytype) void {
    const v = lock.cli();
    defer lock.sti(v);
    _ = std.fmt.format(writer, template, arg) catch unreachable;
}

fn consoleWrite(_: void, bytes: []const u8) console_err!usize {
    if (con) |c| {
        for (bytes) |b| {
            c.write(c, b) catch  return console_err.ConsoleError;
        }
    } else {
        for (bytes) |b| {
            console_buf.write(b);
        }
    }
    return bytes.len;
}

const time = @import("time.zig");
var cursor:time.Timer = undefined;
var time_call:?*const fn() u64 = null;
// called after timer is up
pub fn timeReady(get_time: *const fn() u64) void {
    time_call = get_time;
    cursor = time.Timer{.repeat = 700,.ctx = @ptrFromInt(1), .func = &toggleCursor};
    cursor.node.data = &cursor;
    time.addTimer(&cursor);
}
var cursor_enabled = true;
fn enableCursor(on:bool) void {
    const v = lock.cli();
    defer lock.sti(v);
    cursor_enabled = on;
    if (!on) {
        con.?.cursor(false);
    }
}

fn toggleCursor(t: *time.Timer) void {
    if (!cursor_enabled) return;
    const v = lock.cli();
    defer lock.sti(v);
    const state = @intFromPtr(t.ctx.?);
    switch (state) {
        1 => {con.?.cursor(con.?, true); t.repeat = 700; t.ctx = @ptrFromInt(2);},
        2 => {con.?.cursor(con.?, false); t.repeat = 300; t.ctx = @ptrFromInt(1);},
        else => unreachable
    }
}

fn consoleInput(char:u32) void {
    const l = lock.cli();
    defer lock.sti(l);
    const c = if (char == 0x7f) 0x8 else char;
    if (c == 0x8) {
        if (input_buf.isEmpty()) return;
        var del:[1]u8 = undefined;
        input_buf.readLast(&del, 1) catch unreachable;
    }
    if (!input_buf.isFull()) {
        input_buf.write(@truncate(c)) catch unreachable;
        const ba = [_]u8{@truncate(c)};
        _=writer.write(&ba) catch unreachable;
        if (c == '\n') {
            task.wake(&input_wq);
        }
    } else {
        task.wake(&input_wq);
    }
}

fn consoleControl(code:u32) void {
    switch (code) {
        0x48 => con.?.scroll_up(con.?),
        0x50 => con.?.scroll_down(con.?),
        else => {},
    }
}

const fs = @import("fs.zig");
fn dummyFreePath(_:*fs.MountedFs, _:fs.Path) void {}
const console_fops:fs.FileOps = .{.read = &consoleFileRead, .write = &consoleFileWrite};
const console_fsop:fs.FsOp = .{.stat = undefined, .lookup = undefined, .copy_path = undefined, .free_path = &dummyFreePath};
const console_fs:fs.MountedFs = .{.ops = &console_fsop, .ctx = null, .root = undefined, .fops = &console_fops};

fn consoleFileRead(_:*fs.File, buf:[]u8) anyerror![]u8 {
    var l = lock.cli();
    defer lock.sti(l);
    while (input_buf.isEmpty()) {
        const t = task.getCurrentTask();
        var n = task.WaitQueue.Node{.data = t}; 
        t.state = .sleep;
        input_wq.append(&n);
        lock.sti(l);
        task.schedule();
        l = lock.cli();
    }
    const len = @min(buf.len, input_buf.len());
    try input_buf.readFirst(buf, buf.len);
    return buf[0..len];
}

fn consoleFileWrite(_:*fs.File, buf:[]const u8) anyerror!usize {
    const l = lock.cli();
    defer lock.sti(l);
    return consoleWrite({}, buf);
}
const consoleInputHandler = input.InputHandler{.input = &consoleInput, .control = &consoleControl};

test "ring buf" {
    var rb = console_buf;
    for (0..12) |i| {
        rb.write('a' + @as(u8, @truncate(i)));
    }
    std.debug.print("RingBuffer: {any}\n", .{rb});
    var rbi = rb.iter();
    while (rbi.next()) |c| {
        std.debug.print("char: {c}\n", .{@as(u8, @truncate(c))});
    }
}

