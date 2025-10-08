const lock = @import("lock.zig");
const syscall = @import("syscall.zig");
const std = @import("std");
const Count = std.atomic.Value(u64);
const mem = @import("mem.zig");
const list = @import("lib/list.zig");
pub const FileList = list.List(*File);
//const Path = list.List(*DirEntry);
const object = @import("object.zig");
const io = @import("io.zig");
const task = @import("task.zig");

pub const DEntry = extern struct {
    d_ino:u64 align(1) = 0,
    d_off:i64 align(1) = 0,
    d_reclen:u16 align(1) = 0,
    d_type:u8 align(1) = 0,
    d_name:[0]u8 align(1),
};

var dummy_fs:MountedFs = .{};
var dummy_dentry:DirEntry = .{.name = "dummy"};
var dummy_path:Path = .{.fs = &dummy_fs, .entry = &dummy_dentry};

/// an open file
pub const File = struct {
    ctx:?*anyopaque = null,
    pos:u64 = 0,
    path:Path,
    size:u64 = 0,
    ops:*const FileOps,
    fn dtor(f:*File) void {
        if (f.ops.finalize) |fi| {
            fi(f) catch {};
        }
        if (f.path.fs == &dummy_fs) return;
        f.path.fs.ops.free_path(f.path.fs, f.path);
    }
    pub fn get_new_ex(fops:*const FileOps) !*File {
        const f = try object.new(File, null, &dtor);
        f.pos = 0;
        f.path = dummy_path;
        f.ops = fops;
        return f;
    }
    pub fn get_new(path:Path, fops:*const FileOps) !*File {
        const f = try object.new(File, null, &dtor);
        f.pos = 0;
        f.path = path;
        f.ops = fops;
        return f;
    }
    pub fn get(f:*File) ?*File {
        return object.get(f);
    }

    pub fn put(f:*File) void {
        object.put(f);
    }

    pub fn getType(f:*File) FileType {
        return f.path.entry.type;
    }
};

pub const fn_max = 128;
const alloc = @import("mem.zig").allocator;

pub const Path = struct {
    fs:*MountedFs,
    entry:*DirEntry, 
    pub fn copy(this:@This()) !Path {
        return this.fs.ops.copy_path(this.fs, this);
    }
    pub fn append(this:*@This(), d:*DirEntry) *Path {
        this.entry.next = d;
        d.prev = this.entry;
        d.next = null;
        this.entry = d;
        return this;
    }

    pub fn getRoot(this:*const @This()) *DirEntry {
        var t:?*DirEntry = this.entry;
        var r = this.entry;
        while (t) |rt| {
            r = rt;
            t = rt.prev;
        }
        return r;
    }

    fn put(dst:[]u8, src:[]const u8) ![]u8 {
        if (dst.len >= src.len) {
            @memcpy(dst[0..src.len], src);
            return dst[src.len..];
        }
        return error.OutOfSpace; 
    }

    pub fn getAbsPath(this:*const @This(), buf:[]u8) !usize {
        const r = this.getRoot().next;
        var e:?*DirEntry = r;
        var b = try put(buf, "/");
        while (e) |d| {
            b = try put(b, d.name);
            b = try put(b, "/");
            e = d.next;
        }
        var len = b.ptr - buf.ptr;
        if (len > 1) { // not root 
            len -= 1;
        }
        buf[len] = 0;
        return len + 1;
    }

    pub fn getParent(this:*const @This()) !Path {
        if (this.entry.prev) |_| {
            var cp = try this.copy();
            var last = cp.entry;
            cp.entry = cp.entry.prev.?;
            cp.entry.next = null;
            last.prev = null;
            this.fs.ops.free_path(this.fs, .{.fs = this.fs, .entry = last});
            return cp;
        }
        return try this.fs.root.copy();
    }
};

pub const DirEntry = struct {
    name: []const u8,
    type: FileType = .FILE,
    priv:?*anyopaque = null, // implementation specific
    prev:?*DirEntry = null, // null for root
    next:?*DirEntry = null, // null for the end of the path
};

pub const FileType = enum(u8) {
    FILE,
    DIR,
    LINK
};

pub const FsOp = struct {
    lookup:*const fn(fs:*MountedFs, path:[]const u8, flags:u32, mode:u16) anyerror!Path,
    lookupAt: *const fn(_:*MountedFs, dir:Path, name:[]const u8, flags:u32, mode:u16) anyerror!Path,
    free_path:*const fn(fs:*MountedFs, path:Path) void,
    copy_path:*const fn(fs:*MountedFs, path:Path) anyerror!Path,
    stat:*const fn(fs:*MountedFs, path:Path, stat:*Stat) anyerror!i64,
    mkdir:*const fn(fs:*MountedFs, dir:Path, name:[]const u8, mode:u16) anyerror!void = undefined,
    rmdir:*const fn(fs:*MountedFs, path:[]const u8) anyerror!void = undefined,
    unlink:*const fn(fs:*MountedFs, dir:Path, name:[]const u8) anyerror!void = undefined,
};

pub const FileOps = struct {
    read:*const fn(file:*File, buf:[]u8) anyerror![]u8,
    write:*const fn(file:*File, buf:[]const u8) anyerror!usize,
    // called right before *File is freed
    finalize:?*const fn(file:*File) anyerror!void = null,
    ioctl:?*const fn(file:*File, cmd:u32, arg:u64) i64 = null,
    readdir:?*const fn(file:*File, d:*DEntry, len:u64) anyerror!i64 = null,
};

pub const MountedFs = struct {
    root:Path = undefined, 
    ctx:?*anyopaque = null,
    ops:*const FsOp = undefined,
    fops:*const FileOps = undefined,

};
pub const Stat = extern struct {
	st_dev:u64,
	st_ino:u64,
	st_nlink:u64,

	st_mode:u32,
	st_uid:u32,
	st_gid:u32,
	__pad0:u32,
	st_rdev:u64,
	st_size:u64,
	st_blksize:i64,
	st_blocks:i64,
	st_atime:u64,
	st_atime_nsec:u64,
	st_mtime:u64,
	st_mtime_nsec:u64,
	st_ctime:u64,
	st_ctime_nsec:u64,
	__unused:[3]u64,
    pub fn isCDev(s:*Stat) bool {
        return s.st_mode & 0x2000 == 0x2000;
    }
    pub fn isBDev(s:*Stat) bool {
        return s.st_mode & 0x6000 == 0x6000;
    }
    pub fn isPipe(s:*Stat) bool {
        return s.st_mode & 0x1000 == 0x1000;
    }
};

pub var mounted_fs:*MountedFs = undefined;

pub fn init() void {
    syscall.registerSysCall(syscall.SysCallNo.sys_open, &sysOpen);
    syscall.registerSysCall(syscall.SysCallNo.sys_access, &sysAccess);
    syscall.registerSysCall(syscall.SysCallNo.sys_close, &sysClose);
    syscall.registerSysCall(syscall.SysCallNo.sys_read, &sysRead);
    syscall.registerSysCall(syscall.SysCallNo.sys_readv, &sysReadV);
    syscall.registerSysCall(syscall.SysCallNo.sys_write, &sysWrite);
    syscall.registerSysCall(syscall.SysCallNo.sys_sendfile64, &sysSendFile);
    syscall.registerSysCall(syscall.SysCallNo.sys_readlink, &sysReadLink);
    syscall.registerSysCall(syscall.SysCallNo.sys_readlinkat, &sysReadLinkAt);
    syscall.registerSysCall(syscall.SysCallNo.sys_ioctl, &sysIoCtl);
    syscall.registerSysCall(syscall.SysCallNo.sys_writev, &sysWriteV);
    syscall.registerSysCall(syscall.SysCallNo.sys_mkdir, &sysMkDir);
    syscall.registerSysCall(syscall.SysCallNo.sys_rmdir, &sysRmDir);
    syscall.registerSysCall(syscall.SysCallNo.sys_unlink, &sysUnlink);
    syscall.registerSysCall(syscall.SysCallNo.sys_newstat, &sysStat);
    syscall.registerSysCall(syscall.SysCallNo.sys_lseek, &sysLSeek);
    syscall.registerSysCall(syscall.SysCallNo.sys_fcntl, &sysFCntl);
    syscall.registerSysCall(syscall.SysCallNo.sys_dup, &sysDup);
    syscall.registerSysCall(syscall.SysCallNo.sys_dup2, &sysDup2);
    syscall.registerSysCall(syscall.SysCallNo.sys_chdir, &sysChDir);
    syscall.registerSysCall(syscall.SysCallNo.sys_newfstatat, &sysNewFStatAt);
    syscall.registerSysCall(syscall.SysCallNo.sys_openat, &sysOpenAt);
    syscall.registerSysCall(syscall.SysCallNo.sys_newfstat, &sysFStat);
    syscall.registerSysCall(syscall.SysCallNo.sys_newlstat, &sysLStat);
    syscall.registerSysCall(syscall.SysCallNo.sys_getdents64, &sysGetDents64);
}

const console = @import("console.zig");
pub export fn sysReadLink(path: [*:0]const u8, buf:[*]u8, bufsiz:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    console.print("readlink: {s}\n", .{path});
    _=&path;
    _=&buf;
    _=&bufsiz;
    return -1;
}

pub export fn sysReadLinkAt(dirfd:i32, path: [*:0]const u8, buf:[*]u8, bufsiz:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    console.print("readlink: {s}\n", .{path});
    _=&path;
    _=&buf;
    _=&bufsiz;
    _=&dirfd;
    return -1;
}

pub export fn sysRmDir(path: [*:0]const u8) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    mounted_fs.ops.rmdir(mounted_fs, path[0..len]) catch return -1;
    return 0;
}

pub export fn sysUnlink(path: [*:0]const u8) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    var it = std.mem.splitSequence(u8, path[0..len], "/");
    var last:?[]const u8 = null;
    while (it.next()) |e| {
        if (e.len == 0) continue;
        last = e;
    }
    if (last) |e| {
        const dir = path[0..len - e.len]; 
        if (dir.len > 0) {
            const at = mounted_fs.ops.lookup(mounted_fs, dir, 0, 0) catch return -1;
            defer mounted_fs.ops.free_path(mounted_fs, at);
            mounted_fs.ops.unlink(mounted_fs, at, e) catch return -1;
        } else {
            const cwd = task.getCurrentTask().fs.cwd orelse return -1;
            mounted_fs.ops.unlink(mounted_fs, cwd, e) catch return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

pub export fn sysMkDir(path: [*:0]const u8, mode:u16) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    var it = std.mem.splitSequence(u8, path[0..len], "/");
    var last:?[]const u8 = null;
    while (it.next()) |e| {
        if (e.len == 0) continue;
        last = e;
    }
    if (last) |e| {
        const dir = path[0..len - e.len]; 
        if (dir.len > 0) {
            const at = mounted_fs.ops.lookup(mounted_fs, dir, 0, 0) catch return -1;
            defer mounted_fs.ops.free_path(mounted_fs, at);
            return mkDirAt(at, e, mode);
        } else {
            const cwd = task.getCurrentTask().fs.cwd orelse return -1;
            return mkDirAt(cwd, e, mode);
        }
    } else {
        return -1;
    }
    return 0;
}

fn mkDirAt(dir:Path, name:[]const u8, mode:u16) i64 {
    const p = mounted_fs.ops.lookupAt(mounted_fs, dir, name, 0, 0) catch {
        mounted_fs.ops.mkdir(mounted_fs, dir, name, mode) catch return -1;
        return 0;
    };
    mounted_fs.ops.free_path(mounted_fs, p);
    return -syscall.EEXIST;
}

const AT_FDCWD = -100;

pub export fn sysNewFStatAt(dfd:i32, name: [*:0]const u8, st:*Stat, flags:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const len = std.mem.len(name);
    if (len == 0) return -1;
    if (name[0] == '/') {
        return sysStat(name, st);
    }
    var dir:Path = undefined;
    if (dfd == AT_FDCWD) {
        dir = task.getCurrentTask().fs.cwd.?;
    } else {
        dir = (task.getCurrentTask().fs.open_files.items[@intCast(dfd)] orelse return -1).path;
    }
    const p = mounted_fs.ops.lookupAt(mounted_fs, dir, name[0..len], flags, 0) catch {
        return -syscall.ENOENT; // NOENT
    };
    defer mounted_fs.ops.free_path(mounted_fs, p);
    return mounted_fs.ops.stat(mounted_fs, p, st) catch return -1;
}

pub export fn sysStat(path: [*:0]const u8, st:*Stat) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    const p = mounted_fs.ops.lookup(mounted_fs, path[0..len], 0, 0) catch {
        return -syscall.ENOENT; // NOENT
    };
    defer mounted_fs.ops.free_path(mounted_fs, p);
    return mounted_fs.ops.stat(mounted_fs, p, st) catch return -1;
}

pub export fn sysLStat(path: [*:0]const u8, st:*Stat) callconv(std.builtin.CallingConvention.SysV) i64 {
    return sysStat(path, st);
}

pub export fn sysFStat(fd:u32, st:*Stat) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const file = task.getCurrentTask().fs.open_files.items[fd] orelse return -1;
    return file.path.fs.ops.stat(file.path.fs, file.path, st) catch return -1;
    //return mounted_fs.ops.stat(mounted_fs, file.path, st) catch return -1;
}

pub export fn sysClose(fd:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const tfs = task.getCurrentTask().fs;
    const f = tfs.getFile(fd) orelse return -1;
    tfs.uninstallFd(fd);
    f.put();
    //console.print("closed: {}\n", .{fd});
    return 0;
}
const F_DUPFD  =	0;
const F_DUPFD_CLOEXEC = 1030;

pub export fn sysDup(fd:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const cur = task.getCurrentTask();
    var f = cur.fs.open_files.items[fd] orelse return -1;
    const nfd = cur.fs.getFreeFd() catch return -1;
    f = f.get() orelse return -1;
    cur.fs.installFd(nfd, f);
    return @intCast(nfd);
}

pub export fn sysDup2(fd:u32, nfd:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const cur = task.getCurrentTask();
    if (nfd >= cur.fs.open_files.items.len) {
        cur.fs.ensureUnused(nfd + 1 - cur.fs.open_files.items.len) catch return -1;
    }
    if (cur.fs.open_files.items[nfd]) |_| {
        _=sysClose(nfd);
    }
    var f = cur.fs.open_files.items[fd] orelse return -1;
    f = f.get() orelse return -1;
    cur.fs.installFd(nfd, f); 
    return nfd;
}
const F_GETFD=1;	
const F_SETFD=2;	
const F_GETFL=3;	
const F_SETFL=4;	
pub export fn sysFCntl(fd:u32, cmd:u32, arg:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    switch (cmd) {
    F_DUPFD, F_DUPFD_CLOEXEC => {
        const cur = task.getCurrentTask();
        const mfd:u32 = @intCast(arg);
        const mlen = mfd + 1;
        if (mlen > cur.fs.open_files.items.len) {
            cur.fs.ensureUnused(mlen - cur.fs.open_files.items.len) catch return -1;
        }
        var nfd:i64 = -1;
        for (mfd..cur.fs.open_files.items.len) |i| {
            if (cur.fs.open_files.items[i] == null) {
                nfd = @intCast(i);
                break;
            }
        }
        if (nfd == -1) {
            nfd = @intCast(cur.fs.open_files.items.len);
        }
        return sysDup2(fd, @intCast(nfd));
    },
    F_GETFD, F_SETFD, F_GETFL, F_SETFL => {
        return 0;
    },
    else => std.debug.panic("fcntl command not implemented: {}\n", .{arg})
    }
}

pub export fn sysIoCtl(fd:u32, cmd:u32, arg:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const t = task.getCurrentTask();
    if (fd >= t.fs.open_files.items.len) return -1;
    const f = t.fs.open_files.items[fd] orelse return -1;
    const op = f.ops.ioctl orelse return -1;
    return op(f, cmd, arg);
}

const IoVec = extern struct {
    iov_base:?[*]u8 align(1),
    iov_len:usize align(1)
};

pub export fn sysReadV(fd:u32, vec:[*]IoVec, vlen:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const f = task.getCurrentTask().fs.getFile(fd) orelse return -1;
    var len:i64 = -1;
    for (0..vlen) |v| {
        const vp = &vec[v];
        const iov_base = vp.iov_base orelse continue;
        const r = f.ops.read(f, iov_base[0..vp.iov_len]) catch break;
        len = if (len == -1) @intCast(r.len) else len + @as(i64, @intCast(r.len));
        f.pos += r.len;
        if (r.len < vp.iov_len) {
            break;
        }
    }
    //console.print("readv len: {} from fd: {}, file: 0x{x}\n", .{len, fd, @as(u64, @intFromPtr(f))});
    return len;
}

pub export fn sysWriteV(fd:u32, vec:[*]IoVec, vlen:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    var len:i64 = -1;
    for (0..vlen) |i| {
        const v = &vec[i];
        const vb = v.iov_base orelse continue;
        const r = sysWrite(fd, vb, v.iov_len);
        if (r == -1) {
            break;
        }
        len = if (len == -1) r else len + r;
    }
    return len;
}
// FIXME:
pub var fb_file:*File = undefined;

pub export fn sysChDir(path: [*:0]const u8) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    const fp = mounted_fs.ops.lookup(mounted_fs, path[0..len], 0, 0) 
        catch return -syscall.ENOENT;
    if (fp.entry.type != .DIR) return -1;
    const t = task.getCurrentTask();
    const old = t.fs.cwd.?;
    t.fs.cwd = fp;
    mounted_fs.ops.free_path(mounted_fs, old);
    return 0;
}

pub export fn sysOpenAt(dfd:i32, path: [*:0]const u8, flags:u32, mode:u16) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const t = task.getCurrentTask();
    const fd = t.fs.getFreeFd() catch return -1;
    const len = std.mem.len(path);
    if (len == 0) return -1;
    if (path[0] == '/') {
        return sysOpen(path, flags, mode);
    }
    const file = openAt(dfd, path, flags) catch return -1;
    t.fs.installFd(fd, file);
    return @intCast(fd);

}

pub export fn sysAccess(path: [*:0]const u8, mode:u16) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    const f = mounted_fs.ops.lookup(mounted_fs, path[0..len], 0, mode) catch return -1;
    mounted_fs.ops.free_path(mounted_fs, f);
    return 0;
}

pub export fn sysOpen(path: [*:0]const u8, flags:u32, mode:u16) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&mode;
    const l = lock.cli();
    defer lock.sti(l);
    const t = task.getCurrentTask();
    const fd = t.fs.getFreeFd() catch return -1;
    // TODO: for testing fb, refactor this
    const len = std.mem.len(path);
    if (std.mem.eql(u8, path[0..len], "/dev/fb")) {
         t.fs.installFd(fd, fb_file);
        return @intCast(fd);
    }
    const file = open(path, flags, mode) catch return -1;
    t.fs.installFd(fd, file);
    //console.print("opened: {s} at: {}, addr: 0x{x}\n", .{path, fd, @as(u64, @intFromPtr(file))});
    return @intCast(fd);

}

pub fn openAt(dfd:i32, path: [*:0]const u8, flags:u32) !*File {
    const l = lock.cli();
    defer lock.sti(l);
    const len = std.mem.len(path);
    if (len == 0) return error.InvalidPath;
    var dir:Path = undefined;
    if (dfd == AT_FDCWD) {
        dir = task.getCurrentTask().fs.cwd.?;
    } else {
        dir = (task.getCurrentTask().fs.open_files.items[@intCast(dfd)] orelse return error.InvalidFd).path;
    }
    const p = mounted_fs.ops.lookupAt(mounted_fs, dir, path[0..len], flags, 0) catch {
        return error.FileNotFound; // NOENT
    };
    const file = File.get_new(p, p.fs.fops) catch |err| {
        p.fs.ops.free_path(p.fs, p);
        return err;
    };
    var st:Stat = undefined;
    if (sysNewFStatAt(dfd, path, &st, flags) == 0) {
        file.size = st.st_size;
    }
    return file;
}
pub fn open(path: [*:0]const u8, flags:u32, mode:u16) !*File {
    const len = std.mem.len(path);
    const f = try mounted_fs.ops.lookup(mounted_fs, path[0..len], flags, mode);
    const file = File.get_new(f, f.fs.fops) catch |err| {
        f.fs.ops.free_path(f.fs, f);
        return err;
    };
    var st:Stat = undefined;
    if (sysStat(path, &st) == 0) {
        file.size = st.st_size;
    }
    return file;
}

pub const SeekWhence = enum(u32) {
    set = 0,
    cur = 1,
    end = 2
};

pub export fn sysLSeek(fd: u32, off:i64, whence:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const f = task.getCurrentTask().fs.open_files.items[fd] orelse return -1;
    const s:SeekWhence = @enumFromInt(whence);
    switch (s) {
        .set => f.pos = if (off >= 0) @intCast(off) else 0,
        .cur => {
            const p:i64 = @as(i64, @intCast(f.pos)) + off;
            f.pos = if (p >= 0) @intCast(p) else 0;
        },
        .end => {
            const p:i64 = @as(i64, @intCast(f.size)) + off;
            f.pos = if (p >= 0) @intCast(p) else 0;
        }

    }
    return 0;

}

pub export fn sysGetDents64(fd: u32, buf: *DEntry, len:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const f = task.getCurrentTask().fs.open_files.items[fd] orelse return -1;
    const sz = (f.ops.readdir orelse return -1)(f, buf, len) catch return -1;
    //f.pos += @intCast(sz);
    return sz;
}

pub export fn sysSendFile(out_fd: u32, in_fd: u32, offset:*u64, count:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&offset;
    var st:Stat = undefined;
    if (sysFStat(in_fd, &st) < 0) return -1;
    const len = if (!st.isBDev()) count else @min(count, st.st_size);
    const buf = alloc.alloc(u8, len) catch return -1;
    defer alloc.free(buf);
    const r = sysRead(in_fd, @ptrCast(buf.ptr), len);
    if (r < 0) {
        return r;
    }
    return sysWrite(out_fd, @ptrCast(buf.ptr), @intCast(r));
}

pub export fn sysRead(fd: u32, buf: [*]u8, len:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const f = task.getCurrentTask().fs.getFile(fd) orelse return -1;
    const r = read(f, buf[0..len]) catch {
        return -1;
    };
    //if (r==0) console.print("read from fd {}, file: 0x{x} returned 0\n", .{fd, @as(u64, @intFromPtr(f))});
    return @intCast(r);
}

pub fn read(f:*File, buf:[]u8) !u64 {
    const r = f.ops.read(f, buf) catch |err| {
        return err;
    };
    f.pos += r.len;
    if (r.len == 0 and f.pos < f.size) {
        std.debug.panic("BUG!!", .{});
    }
    return r.len;
}

pub export fn sysWrite(fd: u32, buf: [*]u8, len:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const f = task.getCurrentTask().fs.open_files.items[fd] orelse return -1;
        //TODO: fix this
    const r = (f.ops.write(f, buf[0..len])) catch return -1;
    return @intCast(r);
}

