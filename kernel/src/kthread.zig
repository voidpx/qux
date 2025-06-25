const task = @import("task.zig");
const lock = @import("lock.zig");
const mem = @import("mem.zig");
const CreateArg  = struct {
    arg: ?*anyopaque = null,
    func: *const fn(?*anyopaque) u16,
};

/// create a user thread, the function must finally go to user space
pub fn createUserThread(name:[]const u8, f: *const fn(?*anyopaque) u16, a:?*anyopaque) void {
    var clone_arg = task.CloneArgs{.name = name, .func = f, .arg = a};
    _=task.clone(&clone_arg) catch unreachable;
}

/// create a kernel thread that automaticaly exit when the function returns
pub fn createKThread(name:[]const u8, f: *const fn(?*anyopaque) u16, a:?*anyopaque) void {
    var create_arg = mem.allocator.create(CreateArg) catch unreachable;
    create_arg.arg = a;
    create_arg.func = f;
    var clone_arg = task.CloneArgs{.name = name, .func = &kthread, .arg = create_arg}; 
    _=task.clone(&clone_arg) catch unreachable;
}

pub fn kthread(ca:?*anyopaque) u16 {
    const create_args:*CreateArg = @ptrCast(@alignCast(ca));
    const a = create_args.*;
    mem.allocator.destroy(create_args);
    const code = a.func(a.arg);
    task.taskExit(code);
    return code; // never reached
}



