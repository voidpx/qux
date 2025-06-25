const mem = @import("../mem.zig");
const console = @import("../console.zig");
var font:[]const u8 = undefined;
pub const font_size = 16;
const char_size = (font_size * font_size) / 8;
pub fn init() void {
    const fd = @embedFile("font");
    font = fd[0..fd.len];
}

const cursor_on:[char_size]u8 = .{
    0b00000000,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b01111110,0b00000000,
    0b00000000,0b00000000,
};

const cursor_off:[char_size]u8 = .{
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
    0b00000000,0b00000000,
};
pub fn getGlyph(char: u32) []const u8 {
    const start = char * char_size;
    const end = start + char_size;
    return font[start..end];
}

pub fn getCursor(on:bool) []const u8 {
    return if(on) &cursor_on else &cursor_off; 
}

pub inline fn getCursorWidth() u32 {
    return getCharWidth(0);
}

pub fn getCharWidth(char:u32) u32 {
    return if (char < 256) font_size/2 else font_size;
}

