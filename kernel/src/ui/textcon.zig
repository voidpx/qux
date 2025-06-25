const lock = @import("lock.zig");
const std = @import("std");
const text_base: [*]u16 = @ptrFromInt(0xb8000); 
var console: [*]u16 = text_base;
var cur: [*]u16 = text_base;
var console_end: [*]u16 = text_base + (rows * cols);
const rows: i32 = 25;
const cols: i32 = 80;
const attr: u8 = 7;
const console_err = error{ConsoleError};
pub const writer = std.io.Writer(void, console_err, consoleWrite){ .context = undefined };

pub fn remap_console(comptime mem: type) void {
    console = @ptrFromInt(mem.virtualAddr(@intFromPtr(console)));
    console_end = @ptrFromInt(mem.virtualAddr(@intFromPtr(console_end)));
    cur = @ptrFromInt(mem.virtualAddr(@intFromPtr(cur)));
}

inline fn handleScroll() void {
    if (@intFromPtr(cur) >= @intFromPtr(console_end)) {
        scrollOneRow();
    }
}

fn lf() void {
    const diff = (@intFromPtr(cur) - @intFromPtr(console)) / @sizeOf(u16);
    cur[0] = 0; // clear cursor
    cur += (cols - (diff % cols));
    handleScroll();
}

inline fn cr() void {
    const diff = (@intFromPtr(cur) - @intFromPtr(console)) / @sizeOf(u16);
    cur -= diff % cols;
}

fn putChar(c: u8) void {
    const v = lock.cli();
    defer lock.sti(v);
    switch (c) {
        '\r' => {cr(); return;}, 
        '\n' => {lf(); return;},
        0x8  => {backspace(); return;},
        '\t' => {for (0..4) |_| {putChar(' ');} return;},
        else => {},
    }
    handleScroll();
    cur[0] = (@as(u16, attr) << 8) | c;
    cur += 1;
}

fn consoleWrite(_: void, bytes: []const u8) console_err!usize {
    for (bytes) |b| {
        putChar(b);
    }
    return bytes.len;
}

fn backspace() void {
    const diff = (@intFromPtr(cur) - @intFromPtr(console)) / @sizeOf(u16);
    if (diff % cols == 0) {
        return;
    }
    cur[0] = 0;
    cur -= 1;
    cur[0] = 0;
}

fn scrollOneRow() void {
    for (1..rows) |i| {
        const d = (i - 1) * cols;
        const s = i * cols;
        for (0..cols) |j| {
            const dst: [*]u16 = console + d + j;
            const src: [*]u16 = console + s + j;
            dst[0] = src[0];
        }
    }
    cur = console + (rows - 1) * cols;
    for (0..cols) |i| {
        cur[i] = 0;
    }
}

pub fn clearScreen() void {
    const v = lock.cli();
    defer lock.sti(v);
    for (0..rows * cols) |i| {
        console[i] = 0;
    }
    cur = console;
}

pub fn log(comptime template : []const u8, arg: anytype) void {
    const v = lock.cli();
    defer lock.sti(v);
    if (time_call) |f| {
        const t = f();
        const sec = t / time.nsec_per_sec;
        const msec = (t % time.nsec_per_sec)/time.nsec_per_milli_sec;
        _ = std.fmt.format(writer, "[{}.{d:0>6.6}] ", .{sec, msec}) catch unreachable;
    }
    _ = std.fmt.format(writer, template, arg) catch unreachable;
}
pub fn print(comptime template: []const u8, arg: anytype) void {
    const v = lock.cli();
    defer lock.sti(v);
    _ = std.fmt.format(writer, template, arg) catch unreachable;
}

fn consoleInput(char:u32) void {
    const c = if (char == 0x7f) 0x8 else char;
    const ba = [_]u8{@truncate(c)};
    _=writer.write(&ba) catch unreachable;
}

fn toggleCursor(t: *time.Timer) void {
    const v = lock.cli();
    defer lock.sti(v);
    const state = @intFromPtr(t.ctx.?);
    switch (state) {
        1 => {cur[0] = (@as(u16, attr) << 8) | 219; t.repeat = 700; t.ctx = @ptrFromInt(2);},
        2 => {cur[0] = 0; t.repeat = 300; t.ctx = @ptrFromInt(1);},
        else => unreachable
    }
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

pub fn init() void {
    clearScreen();
    @import("input.zig").registerInputHandler(&consoleInput);
}

