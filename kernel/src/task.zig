const std = @import("std");
const pic = @import("pic.zig");
const idt = @import("idt.zig");
const sig = @import("signal.zig");

const TaskList = std.DoublyLinkedList(*Task);
pub const WaitQueue = std.DoublyLinkedList(*Task);

fn wqPop(wq:*WaitQueue) ?*WaitQueue.Node {
    var n = wq.popFirst() orelse return null;
    n.prev = null;
    n.next = null;
    return n;
}

fn wqRemove(wq:*WaitQueue, n:*WaitQueue.Node) void {
    if ((n.prev == null and n.next == null) or wq.len == 0) return;
    wq.remove(n);
}

pub const TaskState = enum(u8) {
    new,
    running,
    runnable,
    sleep,
    blocked,
    dead,
    reaped,
};
fn vmComp(o1:*anyopaque, o2:*anyopaque) std.math.Order {
    const v1:*VmRange = @alignCast(@ptrCast(o1));
    const v2:*VmRange = @alignCast(@ptrCast(o2));
    return if (v1.start < v2.start) std.math.Order.lt else if (v1.start > v2.start) std.math.Order.gt else std.math.Order.eq;
}
const VmList = std.Treap(*anyopaque, vmComp);
const VmNode = VmList.Node;
pub const VmRange = struct {
    start:u64,
    end:u64,
    node:VmNode = undefined,
    fd:i64 = -1,
    flags:u64 = 0,
    pub fn new() !*VmRange {
        return mem.allocator.create(VmRange);
    }
    pub fn drop(v: *@This(), m:*Mem) void {
        mem.dropUserMemRange(m.pgd, v.start, v.end); 
        return mem.allocator.destroy(v);
    }

    pub fn overlaps(this: *@This(), r: *const VmRange) bool {
        if (this.start >= r.end or this.end <= r.start) {
            return false;
        }
        return true;
    }
};

const object = @import("object.zig");
pub const Mem = struct {
    pub const MAP_NOFT:u64 = 1 << 63; // allocate physical memory directly instead of waiting for page fault
    pgd:*mem.PageTable = undefined,
    vm: VmList = .{},
    brk:u64 = 0,
    fsbase:u64 = 0,
    gsbase:u64 = 0,

    fn available(m: *@This(), size: u64) u64 {
        var it = m.vm.inorderIterator();
        var last_end = mem.user_min;
        const end = mem.user_max;
        while (it.next()) |n| {
            const vr:*VmRange = @alignCast(@ptrCast(n.key));
            if (vr.start > last_end and vr.start - last_end >= size) {
                return last_end;
            }
            last_end = (vr.end + mem.page_size - 1) & ~(mem.page_size - 1);
        }
        return if (end - last_end >= size) last_end else 0;
    }

    pub fn mmap(m: *@This(), start:u64, size:u64, flags:u64) !*VmRange {
        const l = lock.cli();
        defer lock.sti(l);
        var a = start;
        if (a == 0) {
            a = m.available(size);
            if (a == 0) {
                return mem.MemoryError.OutOfMemory; 
            }
        } else {
            if (a < mem.user_min or a > mem.user_max) {
               return mem.MemoryError.InvalidMemory;
            }
            var it = m.vm.inorderIterator();
            //a &= ~(mem.page_size - 1);
            const vr = VmRange{.start = a, .end = a + size};
            while (it.next()) |n| {
                const t = @as(*VmRange, @ptrCast(@alignCast(n.key)));
                if (t.start >= vr.end) break;
                if (t.overlaps(&vr)) {
                    return mem.MemoryError.InvalidMemory;
                }
            }
        }
        var new = try VmRange.new();
        new.start = a;
        new.end = a + size;
        var ent = m.vm.getEntryFor(new);
        ent.set(&new.node);
        if (flags & MAP_NOFT > 0) {
            try mem.mapUserVm(m.pgd, new.start, new.end);
            //console.print("mmap: 0x{x} - 0x{x}\n", .{new.start, new.end});
        } else {
            //console.print("mmap lazy: 0x{x} - 0x{x}\n", .{new.start, new.end});
        }
        return new;
    }

    pub fn findVr(m: *Mem, addr:u64) !*VmRange {
        const l = lock.cli();
        defer lock.sti(l);
        const it = m.vm.inorderIterator();
        while (it.next()) |n| {
            const vr:*VmRange = @ptrCast(n);
            if (addr >= vr.start and addr < vr.end) {
                return n;
            }
        }
        return mem.MemoryError.InvalidMemory; 
    }

    pub fn munmap(m: *@This(), start:u64, size:u64) void {
        const l = lock.cli();
        defer lock.sti(l);
        var v = VmRange{.start = start, .end = start + size};
        //console.print("munmap: 0x{x} - 0x{x}\n", .{v.start, v.end});
        var e = m.vm.getEntryFor(&v);
        if (e.node) |n| {
            var vr:*VmRange = @alignCast(@ptrCast(n.key));
            e.set(null);
            vr.drop(m);
        } else {
            console.print("munmap: 0x{x} - 0x{x}, NOT FOUND\n", .{v.start, v.end});
        }
    }

    pub fn get_new(pgd:*mem.PageTable) !*Mem {
        const o = try object.new(Mem, null, &dtor); 
        o.* = .{};
        o.pgd = pgd;
        return o;
    }

    pub fn get(this:*Mem) !void {
        if (this == &init_mem) return;
        _ = object.get(this);
    }

    pub fn put(this:*Mem) void {
        if (this == &init_mem) return;
        object.put(this);
    }

    fn dtor(this: *Mem) void {
        var it = this.vm.inorderIterator();
        var temp = std.ArrayList(*VmRange).init(mem.allocator);
        defer temp.deinit();
        while (it.next()) |n| {
            temp.append(@ptrCast(@alignCast(n.key))) catch unreachable;
        }
        for (temp.items) |v| {
            v.drop(this);
        }
        mem.dropUserMem(this.pgd); 
    }

    pub fn clone(this:*Mem) !*Mem {
        const pgd = try mem.clonePageTable(this.pgd);
        var new = try get_new(pgd);
        new.brk = this.brk;
        new.fsbase = this.fsbase;
        new.gsbase = this.gsbase;
        var it = this.vm.inorderIterator();
        while (it.next()) |n| {
            const v:*VmRange= @alignCast(@ptrCast(n.key));
            _=try new.mmap(v.start, v.end - v.start, 0); // flag must be 0 
        }
        return new;
    }
};

pub fn getTask(pid:u32) ?*Task {
    var n = task_list.first;
    while (n) |tn| {
        if (tn.data.id == pid) {
            return tn.data;
        }
        n = tn.next;
    }
    return null;
}

pub fn disablePreempt() void {
    _=preempt_disabled.fetchAdd(1, std.builtin.AtomicOrder.acquire);
}

pub fn enablePreempt() void {
    _=preempt_disabled.fetchSub(1, std.builtin.AtomicOrder.release);
}

pub fn preemptDisabled() bool {
    return preempt_disabled.load(std.builtin.AtomicOrder.unordered) > 0;
}
const resched_bit:u8 = 0x01;
const Count = std.atomic.Value(u64);
var preempt_disabled:Count = Count.init(0);
const SchedInfo = struct {
    share:u64 = 0,  // share of cpu
    cpu_enter:i64 = 0, // last seen on cpu
    on_cpu_total:u64 = 0
};

const time = @import("time.zig");
const fs = @import("fs.zig");
const FileList = std.ArrayList(?*fs.File);
const open_file_limit = 64;

const ResourceError = error {
    OutOfFdError
};

pub const TaskFs = struct {
    cwd:?fs.Path = null,
    open_files:FileList,
    open_files_num:u32 = 0,

    pub fn new() !*TaskFs {
        const f= try object.new(TaskFs, null, &drop);
        f.open_files = try FileList.initCapacity(mem.allocator, 8);
        f.open_files.expandToCapacity();
        f.open_files_num = 0;
        @memset(f.open_files.items[0..f.open_files.capacity], null);
        return f;
    }

    pub fn clone(this:*@This()) !*TaskFs {
        const f= try object.new(TaskFs, null, &drop);
        f.open_files = try FileList.initCapacity(mem.allocator, this.open_files.items.len);
        f.open_files.expandToCapacity();
        f.open_files_num = this.open_files_num;
        @memset(f.open_files.items[0..f.open_files.capacity], null);
        for (0..this.open_files.items.len) |i| {
            const of = this.open_files.items[i] orelse continue;
            f.open_files.items[i] = of.get();
        }
        f.cwd = this.cwd.?.copy() catch {
            this.cwd = null;
            this.drop();
            return error.OutOfMemory;
        };
        return f;
    }

    pub fn get(this:*TaskFs) ?*TaskFs {
        return object.get(this);
    }
    pub fn put(this:*TaskFs) void {
        object.put(this);
    }
    pub fn ensureUnused(self:*TaskFs, add:u64) !void {
        std.debug.assert(self.open_files.items.len == self.open_files.capacity);
        const l = self.open_files.items.len;
        try self.open_files.ensureUnusedCapacity(add);
        self.open_files.expandToCapacity();
        @memset(self.open_files.items[l..], null);
    }

    pub fn getFreeFd(self:*TaskFs) !u64 {
        if (self.open_files_num >= open_file_limit) {
            return ResourceError.OutOfFdError;
        }
        for (0..self.open_files.items.len) |i| {
            if (self.open_files.items[i] == null) {
                return i;
            }
        }
        const i = self.open_files.items.len;
        try self.ensureUnused(@min(i, open_file_limit - i));
        std.debug.assert(i < self.open_files.capacity);
        return i;
    }

    pub fn installFd(self:*TaskFs, fd:u64, f:*fs.File) void {
        self.open_files.items[fd] = f;
        self.open_files_num+=1;
    }

    pub fn uninstallFd(self:*TaskFs, fd:u64) void {
        self.open_files.items[fd] = null;
        self.open_files_num-=1;
    }

    pub fn drop(self: *TaskFs) void {
        for (0..self.open_files.items.len) |i| {
            if (self.open_files.items[i]) |f| {
                f.put();
            }
        }
        //console.print("droping mem\n", .{});
        if (self.cwd) |w| {
            w.fs.ops.free_path(self.cwd.?.fs, self.cwd.?);
        }
        self.open_files.deinit();
    }
};

pub const User = struct {
    id:u32 = 0,
    // ... more
};

pub const TaskListener = struct {
    ctx:?*anyopaque = null,
    func:*const fn(ctx:?*anyopaque, t:*Task) void,
    node:TaskListenerList.Node = undefined,
};

const TaskListenerList = std.DoublyLinkedList(*TaskListener);

pub const Task = struct {
    list:TaskList.Node = undefined, 
    child_link:TaskList.Node = undefined,
    stack:u64 = 0,
    state:TaskState = .new,
    flags:u8 = 0,
    exit_code:u16 = 0,
    id:u32 = 0,
    signal:sig.TaskSignal = .{},
    parent:?*Task = null,
    children:TaskList = .{},
    mem:*Mem,
    name:[32]u8 = undefined,
    name_len:usize = 0,
    sp:u64 = 0,
    sched:SchedInfo = .{},
    fs:*TaskFs = undefined,
    pid:u32 = 0, // process id for threads
    user:User = .{},
    exit_wq:WaitQueue = .{},
    threads:TaskList = .{},
    thread_link:TaskList.Node = undefined,
    exit_listeners: TaskListenerList = .{},

    pub fn registerExitListener(t:*@This(), l:*TaskListener) void {
        const f = lock.cli();
        defer lock.sti(f);
        l.node.data = l;
        t.exit_listeners.append(&l.node); 
    }

    pub fn removeExitListener(t:*@This(), l:*TaskListener) void {
        const f = lock.cli();
        defer lock.sti(f);
        t.exit_listeners.remove(&l.node);
    }


    pub fn needResched(t:*@This()) bool {
        return (t.flags & resched_bit) > 0;
    }

    pub fn resched(t:*@This()) void {
        t.flags |= resched_bit;
    }

    pub fn clearResched(t:*@This()) void {
        t.flags &= ~resched_bit;
    }

    pub fn getName(t:*@This()) []u8 {
        return t.name[0..t.name_len];
    }
    pub fn cpuEnter(t:*@This()) void {
        t.sched.cpu_enter = time.getTime().getAsMilliSeconds();
    }
    pub fn cpuExit(t:*@This()) void {
        if (t.sched.cpu_enter != 0) {
            const now = time.getTime().getAsMilliSeconds();
            const share = now - t.sched.cpu_enter;
            t.sched.share += if (share >= 0) @intCast(share) else 0;
            t.sched.cpu_enter = 0;
        }
    }
    pub fn sendSignal(t:*@This(), s:sig.Signal) void {
        const l = lock.cli();
        defer lock.sti(l);
        t.signal.setSignal(s); 
        wakeupTask(t);
    }

    pub fn die(this:*@This()) void {
        const l = lock.cli();
        defer lock.sti(l);
        this.fs.put();
        this.mem.put();
        mem.allocator.destroy(@as(*TaskStack, @ptrFromInt(this.stack)));
        mem.allocator.destroy(this);
        
    }
    pub fn wait(this:*@This()) i32 {
        const t = getCurrentTask();
        if (t == this) {
            console.print("calling wait from the current task!\n", .{});
            return -1;
        }
        const l = lock.cli();
        defer lock.sti(l);
        var node = WaitQueue.Node{.data = t};
        while (this.state != .dead) {
            this.exit_wq.append(&node);
            t.state = .blocked;
            scheduleWithIF();
            // XXX: remove t from the wait queue if it wasn't woken up by child exit ??
            //wqRemove(&this.exit_wq, &node);
        }
        const exit_code = this.exit_code;
        // let the waiter handle the chld signal even the waitee is dead
        this.die();
        return exit_code;
    }
};

fn PriorityCompare(_:void, l:*Task, r:*Task) std.math.Order {
    return if (l.sched.share < r.sched.share) .lt else if (l.sched.share > r.sched.share) .gt else .eq;
}

const task_stack_size = 0x8000;
const RunQueue = std.PriorityQueue(*Task, void, PriorityCompare);
pub var runq:RunQueue = undefined;
var task_list = TaskList{};
var init_task = Task {.mem = &init_mem};

const gdt = @import("gdt.zig");
///XXX: per-cpu
pub var tss = gdt.Tss{};

const mem = @import("mem.zig");
var init_mem:Mem = .{};
const syscall = @import("syscall.zig");
pub fn init() void {
    tss.io_map_base = @sizeOf(@TypeOf(tss)); // io mapping not used
    gdt.loadTSS(&tss);

    const init_stack:u64 = @intFromPtr(@extern(*const u8, .{ .name = "_init_stack" }));
    init_task.stack = init_stack;
    std.debug.assert(mem.k_pgd != 0); // must have been initialized
    init_task.mem.pgd = @ptrFromInt(mem.k_pgd);
    init_task.state = .running;
    init_task.fs = TaskFs.new() catch unreachable;
    init_task.fs.cwd = fs.mounted_fs.root.copy() catch unreachable;
    init_task.fs.installFd(0, console.stdin);
    init_task.fs.installFd(1, console.stdout);
    init_task.fs.installFd(2, console.stderr);
    runq = RunQueue.init(mem.allocator, void{});
    syscall.registerSysCall(syscall.SysCallNo.sys_exit, &sysExit);
    syscall.registerSysCall(syscall.SysCallNo.sys_brk, &sysBrk); 
    syscall.registerSysCall(syscall.SysCallNo.sys_mmap, &sysMMap);
    syscall.registerSysCall(syscall.SysCallNo.sys_munmap, &sysMUnMap);
    syscall.registerSysCall(syscall.SysCallNo.sys_arch_prctl, &sysArchPrctl);
    syscall.registerSysCall(syscall.SysCallNo.sys_set_tid_address, &sysSetTidAddr);
    syscall.registerSysCall(syscall.SysCallNo.sys_set_robust_list, &sysSetRobustList);
    syscall.registerSysCall(syscall.SysCallNo.sys_prlimit64, &sysPrLimit64);
    syscall.registerSysCall(syscall.SysCallNo.sys_mprotect, &sysMProtect);
    syscall.registerSysCall(syscall.SysCallNo.sys_gettid, &sysGetTid);
    syscall.registerSysCall(syscall.SysCallNo.sys_getpid, &sysGetPid);
    syscall.registerSysCall(syscall.SysCallNo.sys_getpgid, &sysGetPGid);
    syscall.registerSysCall(syscall.SysCallNo.sys_setpgid, &sysSetPGid);
    syscall.registerSysCall(syscall.SysCallNo.sys_exit_group, &sysExitGroup);
    syscall.registerSysCall(syscall.SysCallNo.sys_clone, &sysClone);
    syscall.registerSysCall(syscall.SysCallNo.sys_fork, &sysFork);
    syscall.registerSysCall(syscall.SysCallNo.sys_vfork, &sysVFork);
    syscall.registerSysCall(syscall.SysCallNo.sys_getuid, &sysGetUid);
    syscall.registerSysCall(syscall.SysCallNo.sys_geteuid, &sysGetEuid);
    syscall.registerSysCall(syscall.SysCallNo.sys_getppid, &sysGetPPid);
    syscall.registerSysCall(syscall.SysCallNo.sys_getcwd, &sysGetCwd);
    syscall.registerSysCall(syscall.SysCallNo.sys_wait4, &sysWait4);

    sig.init();
    //XXX: special handling for std in/out/err
}

pub export fn sysWait4(pid:i32, status:?*i32, option:i32, ru:?*anyopaque) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    var t:*Task = undefined;
    if (pid == -1) {
        const p = getCurrentTask();
        if (p.children.len > 0) {
            t = @ptrCast(p.children.first.?.data);
        } else {
            return -1;
        }
    } else {
        t = getTask(@intCast(pid)) orelse return -1;
    }
    _=&option;
    _=&ru;
    const code = t.wait();
    if (status) |s| {
        s.* = code;
    }
    return t.id;
}

pub export fn sysGetCwd(buf:[*]u8, size:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    const d = getCurrentTask().fs.cwd orelse return -1;
    if (d.entry.name.len + 1 > size) {
        return -1; // ERANGE
    } else {
        @memcpy(buf[0..d.entry.name.len], d.entry.name);
        buf[d.entry.name.len] = 0;
        return @intCast(d.entry.name.len);
    }
}

pub export fn sysGetUid() callconv(std.builtin.CallingConvention.SysV) i64 {
    return getCurrentTask().user.id;
}

pub export fn sysGetEuid() callconv(std.builtin.CallingConvention.SysV) i64 {
    return getCurrentTask().user.id;
}

pub export fn sysVFork() callconv(std.builtin.CallingConvention.SysV) i64 {
    //console.print("vfork", .{});
    return sysFork();
}

pub export fn sysFork() callconv(std.builtin.CallingConvention.SysV) i64 {
    //console.print("fork", .{});
    const ca = CloneArgs{
    };
    const pid = clone(&ca) catch return -1;
    //console.print("fork {}\n", .{pid});
    return pid;
}

pub export fn sysClone(flags:u64, sp:u64, ptid:?*u32, ctid:?*u32, tls:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    //console.print("clone, flags:0x{x}, sp:0x{x}, ptdi:0x{x}, ctid:0x{x}, tls:0x{x}\n", .{flags, sp, 
    //    if (ptid) |p| @intFromPtr(p) else 0, if (ctid) |p| @intFromPtr(p) else 0, tls});
    _=&ptid;
    _=&ctid;
    _=&tls;
    const ca = CloneArgs{
        .ustack = sp,
        .flags = flags
    };
    const pid = clone(&ca) catch return -1;
    return pid;
}

pub export fn sysGetTid() callconv(std.builtin.CallingConvention.SysV) i64 {
    return getCurrentTask().id;

}

pub export fn sysGetPGid() callconv(std.builtin.CallingConvention.SysV) i64 {
    return getCurrentTask().pid;
}

pub export fn sysSetPGid(pid:u32, pgid:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&pid;
    _=&pgid;
    return 0;
}

pub export fn sysGetPPid() callconv(std.builtin.CallingConvention.SysV) i64 {
    if (getCurrentTask().parent) |p| {
        return p.pid;
    } else {
        return 0;
    }
}

pub export fn sysGetPid() callconv(std.builtin.CallingConvention.SysV) i64 {
    return getCurrentTask().pid;
}

pub export fn sysExitGroup(status:i32) callconv(std.builtin.CallingConvention.SysV) noreturn {
    taskExit(getCurrentTask(), @intCast(status));
    unreachable;
}

pub export fn sysMProtect(addr:*u8, len:usize, prot:i32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&addr;
    _=&len;
    _=&prot;
    const mm = getCurrentTask().mem;
    _=mm.mmap(@intFromPtr(addr), len, 0) catch {
        //console.print("mprotect error: 0x{x}, 0x{x}\n", .{@as(u64, @intFromPtr(addr)), len});
        return 0; // FIXME
    };
    //console.print("mprotect: 0x{x}, 0x{x}\n", .{@as(u64, @intFromPtr(addr)), len});
    return 0;
}

pub const ResLimit = extern struct {
    min:u64 = 0,
    max:u64 = std.math.maxInt(u64),
};

pub export fn sysPrLimit64(pid:u32, res:u32, new:?*ResLimit, old:?*ResLimit) callconv(std.builtin.CallingConvention.SysV) i64 {
   if (old) |o| {
        o.* = ResLimit{};
    }
    _=&pid;
    _=&res;
    _=&new;
    _=&old;
    return 0;
}

const ARCH_SET_GS =0x1001;
const ARCH_SET_FS =0x1002;
const ARCH_GET_FS =0x1003;
const ARCH_GET_GS =0x1004;
const msr = @import("msr.zig");
pub export fn sysArchPrctl(op:i32, option:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    switch (op) {
        ARCH_SET_FS=> {
            //asm volatile("movw $0, %fs");
            //console.print("ARCH_SET_FS:0x{x}\n", .{option});
            getCurrentTask().mem.fsbase = option;
            msr.wrmsr(msr.MSR_FS_BASE, option);
        },
        else => unreachable

    }
    _=&op;
    _=&option;
    return 0;
}

pub export fn sysSetTidAddr(addr:?*u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&addr; // add this to Task
    return getCurrentTask().id;
}

pub export fn sysSetRobustList(addr:u64, len:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&addr; // add this to Task
    _=&len;
    return -1;
}


pub export fn sysBrk(addr:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const mm = getCurrentTask().mem;
    if (mm.brk < addr) {
        _=mm.mmap(mm.brk, addr - mm.brk, Mem.MAP_NOFT) catch return @intCast(mm.brk);
        //console.print("sysBrk: 0x{x}, current brk:0x{x}\n", .{addr, mm.brk});
        mm.brk = addr;
        return 0;
    } else if (addr != 0) {
        //console.print("sysBrk shrink: 0x{x}, current brk:0x{x}\n", .{addr, mm.brk});
    }
    return @intCast(mm.brk);
}

pub export fn sysMMap(addr:u64, len:u64, prot:i32, flags:i32, fd:i32, off:u64)
    callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&prot;
    _=&flags;
    _=&fd;
    _=&off;
    const mm = getCurrentTask().mem;
    const a = mm.mmap(addr, len, Mem.MAP_NOFT) catch {
        console.print("unable to mmap: 0x{x} - 0x{x}\n", .{addr, addr + len});
        return -1;
    };

    //console.print("mmap 0x{x}, len:0x{x}, at:0x{x}\n", .{addr, len, a.start});
    return @intCast(a.start);
}
pub export fn sysMUnMap(addr:u64, len:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const mm = getCurrentTask().mem;
    mm.munmap(addr, len); 
    //console.print("munmap 0x{x}, len:0x{x}\n", .{addr, len});
    return 0;
}

pub const CLONE_VM:u64 = 0x100;

pub const CloneArgs = struct {
    func:?*const fn(arg: ?*anyopaque) u16 = null,
    arg:?*anyopaque = null,
    name:[]const u8 = "",
    ustack: u64 = 0, // user stack
    flags: u64 = 0,
    tls: u64 = 0,
    pub fn new(flags:u64) CloneArgs {
        return .{.flags = flags};
    }
    pub fn shareVM(this:@This()) bool {
        return this.flags & CLONE_VM == CLONE_VM;
    }
};

pub fn getTotalTasks() usize {
    return task_list.len;
}

// DEBUG
const runq_min_cap:u32 = 8;
pub fn reapTasks() void {
    const v = lock.cli();
    defer lock.sti(v);
    var n = task_list.first;
    while (n) |t| {
        const next = t.next;
        const proc = t.data;
        if (proc.state == .dead) {
            console.print("reaping dead task {s}\n", .{proc.getName()});
            task_list.remove(t);
            // TODO: re-parent children
            proc.die();
        }
        n = next;
    }
    if (runq.len < runq.capacity() / 2) {
        runq.shrinkAndFree(@min(@max(runq.len, runq_min_cap), runq.capacity()));
    }
}

pub const TaskStack = [task_stack_size]u8; 
inline fn dupTask(cur:*Task) !*Task {
    const t = try mem.allocator.create(Task);
    t.* = cur.*;
    return t;
}

// XXX: per cpu
var cur_task:*Task = &init_task;
pub fn getCurrentTask() *Task {
    return cur_task;
}

const lock = @import("lock.zig");

const NewTaskFrame = extern struct {
    rbp:u64 = 0,
    rbx:u64 = 0,
    r12:u64 = 0,
    r13:u64 = 0,
    r14:u64 = 0,
    r15:u64 = 0,
    ret_addr:u64,
    state:idt.IntState
};

pub fn startSchedRoutine() void {
    _=clone(&.{.func = &schedRoutine, .arg = null, .name = "sched_routine"}) catch unreachable;
}

fn schedRoutine(_:?*anyopaque) u16 {
    while (true) {     
        _=time.sleep(&.{.sec = 5 * 60}, null);
        const v = lock.cli();
        defer lock.sti(v);
        const min = if (runq.peek()) |f| f.sched.share else 0;
        var it = runq.iterator(); 
        if (min >= 0) {
            while (it.next()) |t| {
                t.sched.share -= min;
            }
            // cur is not in runq
            getCurrentTask().sched.share -= min;
        }
    }
}

fn switchTask(cur:*Task, to:*Task) void {
    //console.print("switch task 0x{x} => 0x{x}, {} => {}\n", 
    //   .{@as(u64, @intFromPtr(cur)), @as(u64, @intFromPtr(to)), cur.id, to.id});
    cur_task = to;
    cur_task.clearResched();
    if (cur.mem.pgd != to.mem.pgd) {
        mem.loadCR3(@intFromPtr(to.mem.pgd));
    }
    __switchTask(cur, to, &cur.sp, &to.sp);
    finishTaskSwitch(null, null, switch_cli);

}

fn scheduleEnter(_:*Task) bool {
    disablePreempt();
    return lock.cli();
}
fn scheduleExit(t:*Task) void {
    t.state = .running;
    enablePreempt();
    lock.sti(switch_cli);
}

var switch_cli:bool = false;
export fn finishTaskSwitch(
    func:?*anyopaque, arg:?*anyopaque, new:bool) 
    callconv(std.builtin.CallingConvention.SysV) void {
    const t = getCurrentTask();
    msr.wrmsr(msr.MSR_FS_BASE, t.mem.fsbase);
    msr.wrmsr(msr.MSR_GS_BASE, t.mem.gsbase);
    tss.sp0 = getCurrentSP0();
    if (new) {
        switch_cli = true;
    }
    t.cpuEnter();
    scheduleExit(t);
    if (new) {
        if (func) |f| { // kernel thread
            const fp: *const fn(a:?*anyopaque) u16 = @ptrCast( f);
            const ret = fp(arg);
            _=&ret;
        }
        getCurrentState().rax = 0;
    }
}

extern fn __switchTask(cur:*Task, to:*Task, cur_sp:*u64, next_sp:*u64) void;

export fn newTaskExitCall(state: *idt.IntState) callconv(std.builtin.CallingConvention.SysV) void {
    _=&state;
    return;
}

const as = @import("asm.zig");
comptime {
    asm (
    \\
    \\.pushsection ".text", "ax", @progbits
    \\.global newTaskEntry
    \\.global __switchTask
    \\.type newTaskEntry, @function
    \\.type __switchTask, @function
    \\newTaskEntry:
    \\  mov $0, %rbp
    \\  mov %r12, %rsi //arg
    \\  mov %rbx, %rdi //fn
    \\  mov $1, %rdx
    \\  call finishTaskSwitch
    \\entry_call_return newTaskExitCall
    \\  
    \\__switchTask:
    \\ push %r15
    \\ push %r14
    \\ push %r13
    \\ push %r12
    \\ push %rbx
    \\ push %rbp
    \\ mov %rsp, (%rdx)
    \\ mov (%rcx), %rsp
    \\ pop %rbp
    \\ pop %rbx
    \\ pop %r12
    \\ pop %r13
    \\ pop %r14
    \\ pop %r15
    \\ ret 
    \\.popsection  
    \\
    );
}

fn pickTask() *Task {
    const cur = getCurrentTask();
    if (cur != &init_task and cur.state == .running) {
        addToRunQueue(cur);
    }
    // XXX: strategy goes here
    var picked:?*Task = null;
    while (true) {
        const n = runq.removeOrNull() orelse break; 
        if (n.state == .runnable) {
            picked = n;
            break;
        }
    }
    return picked orelse &init_task;
}


pub export fn sysExit(code: u16) callconv(std.builtin.CallingConvention.SysV) void {
    taskExit(getCurrentTask(), code);
}

fn exitTask(t:*Task, code:u16) void {
    if (t.state == .dead) return;
    if (t.id == t.pid) { // the process
        //console.print("process exit: {}\n", .{t.id});
        while (t.threads.popFirst()) |n| {
           exitTask(n.data, code); 
        }
    } else {
        //console.print("thread exit: {}\n", .{t.id});
    }
    t.exit_code = code;
    t.state = .dead;
    while (t.exit_listeners.popFirst()) |n| {
        const l = n.data;
        l.func(l.ctx, t);
    }
    if (t.parent) |p| {
        p.children.remove(&t.child_link);
        p.sendSignal(.chld); //TODO: handle this
    }
    task_list.remove(&t.list);
    wakeup(&t.exit_wq);
}

pub fn taskExit(t:*Task, code: u16) callconv(std.builtin.CallingConvention.SysV) void {
    const cur = getCurrentTask();
    if (t != cur) {
        t.sendSignal(.int);
    } else {
        const v = lock.cli();
        exitTask(t, code);
        lock.sti(v);
        // must not free the stack, schedule runs on it
        // let its parent reap it
        schedule(); 
    }
}

fn addToRunQueue(t:*Task) void {
    if (t.state == .dead) return;
    t.state = .runnable;
    runq.add(t) catch unreachable; // XXX: handle this
}

pub fn wakeupTask(t:*Task) void {
    const v = lock.cli();
    defer lock.sti(v);
    wakeupTaskUnlocked(t);
}

fn wakeupTaskUnlocked(t:*Task) void {
    if (t.state != .dead and t.state != .runnable) {
        t.sched.share = if (runq.peek()) |s| s.sched.share  else 0;
        addToRunQueue(t);
    }
}

pub fn wait(wq: *WaitQueue) void {
    const l = lock.cli();
    defer lock.sti(l);
    const t = getCurrentTask();
    t.state = .blocked;
    var node = WaitQueue.Node{.data = t};
    wq.append(&node);
    scheduleWithIF();
}

pub fn wakeup(wq:*WaitQueue) void {
    const v = lock.cli();
    defer lock.sti(v);
    while (wqPop(wq)) |n| {
        const t = n.data;
        wakeupTaskUnlocked(t);
    }
}

const console = @import("console.zig");

pub fn scheduleWithIF() void {
    lock.sti(true);
    schedule();
    _=lock.cli();
}
    
pub fn schedule() void {
    const cur = getCurrentTask();
    const cli = scheduleEnter(cur);
    const t = pickTask();
    if (cur == t) {
        scheduleExit(t);
        return;
    }
    cur.cpuExit();
    switch_cli = cli;
    switchTask(cur, t);
}

extern fn newTaskEntry() void;

pub fn getCurrentState() *idt.IntState {
    const state = taskRegs(getCurrentTask());
    return state;
}

pub fn getCurrentSP0() u64 {
    return getCurrentTask().stack + task_stack_size;
}

fn taskRegs(t:*Task) *idt.IntState {
    const s = t.stack + task_stack_size - @sizeOf(idt.IntState);
    return @ptrFromInt(s);
}

/// preemption must be disabled when entering
fn setupTask(a:*const CloneArgs, task:*Task, cur:*Task) !void {
    task.id = task_id;
    task_id += 1;
    const stack = try mem.allocator.create(TaskStack);
    task.stack = @intFromPtr(stack);
    task.list = .{.prev = null, .next = null, .data = task};
    task.children = .{};
    const len = @min(task.name.len, a.name.len);
    @memcpy(@as([*]u8, &task.name), a.name[0..len]);
    const last = if (len<task.name.len) len else task.name.len - 1;
    task.name[last] = 0;
    task.name_len = last;
    const fp = task.stack + task_stack_size - @sizeOf(NewTaskFrame);
    var frame:*NewTaskFrame = @ptrFromInt(fp);
    @memset(@as([*]u8, @ptrCast(frame))[0..@sizeOf(NewTaskFrame)], 0);
    frame.ret_addr = @intFromPtr(&newTaskEntry);
    task.pid = cur.pid;
    if (a.func) |f| { // kernel thread
        frame.rbx = @intFromPtr(f);
        frame.r12 = if (a.arg) |arg| @intFromPtr(arg) else 0;
        try task.mem.get();
        task.fs = task.fs.get() orelse unreachable;
    } else {
        frame.rbx = 0;
        frame.rbp = 0;
        frame.r12 = 0;
        frame.r13 = 0;
        frame.r14 = 0;
        frame.r15 = 0;
        frame.state = taskRegs(cur).*;
        //const is = taskRegs(task);
        //console.print("state:{any}\n", .{is});
        if (a.ustack != 0) {
            taskRegs(task).rsp = a.ustack;
        }
        if (!a.shareVM()) { // process
            task.pid = task.id;
            task.mem = cur.mem.clone() catch unreachable;
            task.fs = try cur.fs.clone();
            task.fs.installFd(0, cur.fs.open_files.items[0].?.get().?);
            task.fs.installFd(1, cur.fs.open_files.items[1].?.get().?);
            task.fs.installFd(2, cur.fs.open_files.items[2].?.get().?);

        } else { // thread
            task.pid = cur.pid;
            try task.mem.get();
            task.fs = cur.fs.get().?;
            const proc = getTask(cur.pid) orelse unreachable;
            task.thread_link = .{.data = task};
            proc.threads.append(&task.thread_link);
        }
        if (a.tls != 0) {
            task.mem.fsbase = a.tls;
        }
    }
    task.list = .{.prev = null, .next = null, .data = task};
    task_list.append(&task.list);
    task.sp = fp;
    task.parent = cur;
    task.signal = .{};
    task.signal.sig_actions = .{sig.SigAction{}}**64;
    task.child_link.data = task;
    cur.children.append(&task.child_link);
    task.sched = .{};
    task.sched.share = if (runq.peek()) |t| t.sched.share else 0; 
}

var task_id:u32 = 1;
pub fn clone(a: *const CloneArgs) !u32 {
    const v = lock.cli();
    defer lock.sti(v);
    const cur = getCurrentTask();
    const task = try dupTask(cur);
    try setupTask(a, task, cur);
    addToRunQueue(task);
    return task.id;

}


