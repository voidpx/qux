const bi = @import("../bootinfo.zig");
var fb:bi.FrameBuffer = undefined;
var fb_end:u64 = undefined;
var fb_size:u64 = undefined;
const font = @import("font.zig");
const con = @import("../console.zig");
const std = @import("std");
const bg_color:u32 = 0x043c4a; //0x3c7482;
const fg_color:u32 = 0xffffff;
var scr_lines:u32 = 0;
var font_pitch:u32 = undefined;
var v_lines:u32 = undefined;
const mem = @import("../mem.zig");
pub fn fbWidth() u32 {
    return fb.framebuffer_width;
}

pub fn fbHeight() u32 {
    return fb.framebuffer_height;
}

pub fn getLineSize() usize {
    return fb.framebuffer_width / font.font_size * 2;
}

fn newLine(_:*con.LineBuffer) !*con.Line {
    const l = try mem.allocator.create(con.Line); 
    const ld = try mem.allocator.alloc(u32, getLineSize());
    l.* = .{.line = ld};
    return l;
}

fn addToLine(_:*con.LineBuffer, line:*con.Line, char:u32) void {
    const cs = font.getCharWidth(char);
    std.debug.assert(fbWidth() - line.scr_cursor >= cs and line.len < line.line.len);
    line.line[line.len] = char;
    line.len += 1;
    
}

fn canAddToLine(_:*con.LineBuffer, line:*con.Line, char:u32) bool {
    const cs = font.getCharWidth(char);
    return fbWidth() - line.scr_cursor >= cs and line.len < line.line.len; 
}

const lc = con.LineControl{.new_line = &newLine};

fn eraseLine(row:u32) void {
    std.debug.assert(row < scr_lines);
    const r = fb.framebuffer_addr + row * font_pitch;
    const ra:[]u32 = @as([*]u32, @ptrFromInt(r))[0..font_pitch/@sizeOf(u32)];
    @memset(ra, bg_color);
}

var line_buf = con.LineBuffer{.line_control = &lc};
var bytepp:u32 = undefined;

fn drawCursor(r:u32, c:u32, on:bool) void {
    const cr = font.getCursor(on);
    drawBitmap(r, c, cr, font.getCursorWidth());
}

const FbCon = struct {
    buf:*con.LineBuffer,
    v_first:?*con.Line,
    v_last:?*con.Line,
    v_lines:u32 = 0,
    fn cursor(self:*@This(), on:bool) void {
        if (self.buf.last) |l| {
            const idx = l.index;
            if (idx >= 0 and idx < scr_lines) {
                var r:u32 = @intCast(l.index * font.font_size);
                var c = l.scr_cursor;
                if (l.scr_cursor >= fbWidth()) {
                    const line = self.appendLine() catch std.debug.panic("OOM", .{});
                    r = @intCast(line.index * font.font_size);
                    c = line.scr_cursor;
                }
                drawCursor(r, c, on);
            }
        }
    }
    inline fn scrollDownToAddLine(self:*@This()) void {
        self.scrollToBottom(true);
    }
    fn scrollToBottom(self:*@This(), nl:bool) void {
        while (true) {
            const off = if (self.buf.last) |last| @as(u32, @intCast(last.index)) * font.font_size * fb.framebuffer_pitch else 0;
            const c = if (nl) off + font_pitch else off;
            const nla = fb.framebuffer_addr + c;
            if (nla >= fb_end) {
                self.scroll_down();
            } else {
                break;
            }
        }
    }
    inline fn scrollDownToLastLine(self:*@This()) void {
        self.scrollToBottom(false);
    }

    fn drawLine(_:*@This(), line:*con.Line, dst_idx:u32) void {
        line.scr_cursor = 0;
        line.index = @intCast(dst_idx);
        for (0..line.len) |i| {
            const char = line.line[i];
            const w = font.getCharWidth(char);
            drawCharWithWidth(dst_idx * font.font_size, line.scr_cursor, char, w);
            line.scr_cursor += w;
        }
        erase(@intCast(line.index * font.font_size), line.scr_cursor, fb.framebuffer_width - line.scr_cursor, font.font_size, bg_color);
    }

    fn scroll_down(self:*@This()) void {
        if (self.v_first == null or self.v_first.?.next == null) return;
        var line = self.v_first;
        var idx:i32 = 0;
        while (line) |l| {
            idx = l.index;
            if (idx >= scr_lines) {
                break;
            }
            l.index -= 1;
            if (l.index >= 0) {
               self.copyLine(@intCast(l.index), @intCast(idx)); 
            }
            line = l.next;
        }
        if (idx >= scr_lines) {
            self.drawLine(line.?, scr_lines - 1);
            self.v_last = line;
        } else {
            eraseLine(@intCast(idx));
        }
        if (self.v_first.?.index < 0) {
            self.v_first = self.v_first.?.next;
        }

    }
    fn copyLine(_:*@This(), dst:u32, src:u32) void {
        if (dst == src) return;
        const r = fb.framebuffer_addr + dst * font_pitch;
        const rn = fb.framebuffer_addr + src * font_pitch;
        const row:[]u8 = @as([*]u8, @ptrFromInt(r))[0..font_pitch];
        const rown:[]u8 = @as([*]u8, @ptrFromInt(rn))[0..font_pitch];
        @memcpy(row, rown);
    }
    fn scroll_up(self:*@This()) void {
        if (self.v_first == self.buf.first) {
            return; // alrady at the top
        }
        if (self.v_last == null or self.v_last.?.prev == null) return;
        var line = self.v_last;
        var idx:i32 = 0;
        while (line) |l| {
            idx = l.index;
            if (idx < 0) {
                break;
            }
            l.index += 1;
            if (l.index < scr_lines) {
               self.copyLine(@intCast(l.index), @intCast(idx)); 
            }
            line = l.prev;
        }
        if (idx < 0) {
            self.drawLine(line.?, 0);
            self.v_first = line;
        } else {
            eraseLine(@intCast(idx));
        }
        if (self.v_last.?.index >= scr_lines) {
            self.v_last = self.v_last.?.prev;
        }
    }
    fn backspace(self:*@This()) void {
        self.scrollDownToLastLine();
        if (self.buf.last) |last| {
            if (last.len > 0) {
                const char = last.line[last.len-1];
                last.len -= 1;
                const cw = font.getCharWidth(char);
                last.scr_cursor = last.scr_cursor - cw;
                erase(@intCast(last.index * font.font_size), last.scr_cursor, cw, font.font_size, bg_color);
            }
        }
    }
    fn appendLine(self:*@This()) !*con.Line {
        if (self.buf.last != null and self.buf.last.?.index >= scr_lines) {
            //XXX: scroll to the bolltom
        }
        if (self.buf.first != null) {
            self.scrollDownToAddLine();
        }
        const prev = self.buf.last;
        const line = try self.buf.appendLine();
        if (prev) |p| {
            line.index = p.index + 1;
        } else {
            self.v_first = line; 
        }
        self.v_last = line;
        return line;
        
    }
    fn write(self:*@This(), char:u32) !void {
        self.scrollDownToLastLine();
        if (char == '\n') {
            _ = try self.appendLine();
            return;
        }
        if (char == 0x8) {
            self.backspace();
            return;
        }
        var last = self.buf.last;
        if (last == null or !canAddToLine(self.buf, last.?, char)) {
            last = try self.appendLine();
        }
        var ln = last.?;
        ln.add(char);
        const coord = self.coordinate();
        const fw = font.getCharWidth(char);
        drawCharWithWidth(coord.r, coord.c, char, fw);
        ln.scr_cursor = coord.c + fw; 

    }
    fn coordinate(self:*@This()) struct {r:u32, c:u32} {
        if (self.buf.last) |last| {
            return .{.r = @as(u32, @intCast(last.index)) * font.font_size, .c = last.scr_cursor};
        }
        return .{.r = 0, .c = 0};
    }
};

var fbcon:FbCon = undefined;

var console:con.Con = .{.ctx = &fbcon, 
    .write = &write,
    .cursor = &cursor,
    .scroll_up = &scroll_up,
    .scroll_down = &scroll_down,
};

fn scroll_up(this:*con.Con) void {
    const fbc:*FbCon = @alignCast(@ptrCast(this.ctx.?)); 
    fbc.scroll_up();
}

fn scroll_down(this:*con.Con) void {
    const fbc:*FbCon = @alignCast(@ptrCast(this.ctx.?)); 
    fbc.scroll_down();
}

fn write(this:*con.Con, char:u32) !void {
    const fbc:*FbCon = @alignCast(@ptrCast(this.ctx.?)); 
    try fbc.write(char);
}

fn cursor(this:*con.Con, on:bool) void {
    const fbc:*FbCon = @alignCast(@ptrCast(this.ctx.?));
    fbc.cursor(on);
}


// before vm setup
pub fn init(mb2:*bi.Mb2) void {
    const fbp = mb2.get(bi.FrameBuffer, bi.TagType.mb2_tag_type_framebuffer).?;
    fb = fbp.*;
    bytepp = fb.framebuffer_bpp / 8; 
}

const fs = @import("../fs.zig");

const fbfs:fs.MountedFs = .{.ctx = null, 
    .ops = &fbfsops, 
    .root = undefined,
    .fops = &fbfsfops
};

const fbfsops:fs.FsOp = .{
    .lookup = undefined,
    .copy_path = undefined,
    .free_path = undefined,
    .stat = undefined
};

const fbfsfops:fs.FileOps = .{
    .read = undefined,
    .write = &fwrite
};

var fb_file:fs.File = undefined;

fn fwrite(file:*fs.File, buf:[]const u8) anyerror!usize {
    _=&file;
    const len = @min(buf.len, fb_size);
    @memcpy(@as([*]u8, @ptrFromInt(fb.framebuffer_addr)), buf[0..len]);
    return len;
}

// after vm setup
pub fn remap() void {
    const fbphy = fb.framebuffer_addr;
    fb.framebuffer_addr = mem.virtualAddr(fb.framebuffer_addr);
    scr_lines = fb.framebuffer_height / font.font_size;
    fb_size = fb.framebuffer_height * fb.framebuffer_pitch;
    fb_end = fb.framebuffer_addr + fb_size;
    font_pitch = fb.framebuffer_pitch * font.font_size;
    const size = fb.framebuffer_width * fb.framebuffer_height * fb.framebuffer_bpp / 8;
    mem.kernelMapVm(fb.framebuffer_addr, fb.framebuffer_addr + size, fbphy >> mem.page_shift) catch unreachable;
    for (0..fb.framebuffer_height) |i| {
        for (0..fb.framebuffer_width) |j| {
            const p = @as(*u32, @ptrFromInt(fb.framebuffer_addr + (j*(fb.framebuffer_bpp/8) + fb.framebuffer_pitch * i )));
            p.* = bg_color;
        }
    }
    fbcon = .{.buf = &line_buf, .v_first = null, .v_last = null};
    con.registerConsole(&console); 
    fb_file = fs.File{.ops = &fbfsfops, .pos = 0, .path = undefined};
    fs.fb_file = &fb_file;
}

fn showWelcome() void {
    const welcome = "Welcome"; 
    const i:u32 = fbHeight()/2 - 16;
    var j:u32 = fbWidth()/2 - 5*16;
    for (welcome) |c| {
        drawChar(i, j, c);
        j+=font.getCharWidth(c) ;
    }
    drawChar(i, j, 0x20);
    j+=font.font_size;
    drawChar(i, j, 0x6b22);
    j+=font.font_size;
    drawChar(i, j, 0x8fce);
}

fn erase(r:u32, c:u32, w:u32, h:u32, color:u32) void {
    for (0..h) |i| {
        for (0..w) |j| {
            drawPixel(@truncate(r + i), @truncate(c + j), color);
        }
    }
}

inline fn drawPixel(r:u32, c:u32, color:u32) void {
    const p = @as(*u32, @ptrFromInt(fb.framebuffer_addr + c*(bytepp) + fb.framebuffer_pitch * r));
    p.* = color;
}

fn drawBitmap(r:u32, c:u32, bm:[]const u8, w:u32) void {
    var i:u32 = 0;
    var j:u32 = 0;
    var idx:u32 = 0;
    outer:while (idx < bm.len) {
        const b = bm[idx];
        for (0..8) |n| {
            if (j < w) {
                const on = (b & (@as(usize, 1)<<@truncate(n))) > 0; 
                drawPixel(r + i, c + j, if (on) fg_color else bg_color);
                j+=1;
                if (j % font.font_size == 0) {
                    i+=1;
                    j = 0;
                }
            } else {
                const delta = font.font_size - w;
                idx += delta/8;
                i+=1;
                j = 0;
                continue :outer;
            }
        }
        idx += 1;
    }
}

fn drawCharWithWidth(r:u32, c:u32, char:u32, fw:u32) void {
    const fd = font.getGlyph(char);
    drawBitmap(r, c, fd, fw);
}

fn drawChar(r:u32, c:u32, char:u32) u32 {
    const fw = font.getCharWidth(char);
    drawCharWithWidth(r, c, char, fw);
    return fw;
}

