const std = @import("std");

pub fn main() !void {
    while (true) {
        std.debug.print("greetings from user space!\n", .{});
        std.time.sleep(10000000000);
    }
}

