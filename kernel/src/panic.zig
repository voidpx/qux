const console = @import("console.zig");
const std = @import("std");
pub fn call(msg: []const u8, ert: ?*std.builtin.StackTrace, ra: ?usize) noreturn {
    _=ra;
    console.print("kernel panicked: {s}\n", .{msg});
    if (ert) |t| {
        if (t.instruction_addresses.len > 0) {
            const a = t.instruction_addresses[0];
            console.print("at: 0x{x}\n", .{a});
        }
    }
    while (true) {
        asm volatile("cli; hlt");
    }
}

pub fn sentinelMismatch(expected: anytype, found: @TypeOf(expected)) noreturn {
    _ = found;
    call("sentinel mismatch", null, null);
}

pub fn unwrapError(ert: ?*std.builtin.StackTrace, err: anyerror) noreturn {
    _ = ert;
    _ = &err;
    call("attempt to unwrap error", null, null);
}

pub fn outOfBounds(index: usize, len: usize) noreturn {
    _ = index;
    _ = len;
    call("index out of bounds", null, null);
}

pub fn startGreaterThanEnd(start: usize, end: usize) noreturn {
    _ = start;
    _ = end;
    call("start index is larger than end index", null, null);
}

pub fn inactiveUnionField(active: anytype, accessed: @TypeOf(active)) noreturn {
    _ = accessed;
    call("access of inactive union field", null, null);
}
