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
        f.path.fs.ops.free_path(f.path.fs, f.path);
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
};

pub const DirEntry = struct {
    name: []const u8,
    priv:?*anyopaque = null, // implementation specific
    prev:?*DirEntry = null, // null for root
    next:?*DirEntry = null, // null for the end of the path
};

pub const FsOp = struct {
    lookup:*const fn(fs:*MountedFs, path:[]const u8, flags:u32) anyerror!Path,
    free_path:*const fn(fs:*MountedFs, path:Path) void,
    copy_path:*const fn(fs:*MountedFs, path:Path) anyerror!Path,
    stat:*const fn(fs:*MountedFs, path:Path, stat:*Stat) anyerror!i64
};

pub const FileOps = struct {
    read:*const fn(file:*File, buf:[]u8) anyerror![]u8,
    write:*const fn(file:*File, buf:[]const u8) anyerror!usize,
    finalize:?*const fn(file:*File) anyerror!void = null,
};

pub const MountedFs = struct {
    root:Path, 
    ctx:?*anyopaque,
    ops:*const FsOp,
    fops:*const FileOps,

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
};

pub var mounted_fs:*MountedFs = undefined;

pub fn init() void {
    syscall.registerSysCall(syscall.SysCallNo.sys_open, &sysOpen);
    syscall.registerSysCall(syscall.SysCallNo.sys_close, &sysClose);
    syscall.registerSysCall(syscall.SysCallNo.sys_read, &sysRead);
    syscall.registerSysCall(syscall.SysCallNo.sys_readv, &sysReadV);
    syscall.registerSysCall(syscall.SysCallNo.sys_write, &sysWrite);
    syscall.registerSysCall(syscall.SysCallNo.sys_readlink, &sysReadLink);
    syscall.registerSysCall(syscall.SysCallNo.sys_readlinkat, &sysReadLinkAt);
    syscall.registerSysCall(syscall.SysCallNo.sys_ioctl, &sysIoCtl);
    syscall.registerSysCall(syscall.SysCallNo.sys_writev, &sysWriteV);
    syscall.registerSysCall(syscall.SysCallNo.sys_mkdir, &sysMkDir);
    syscall.registerSysCall(syscall.SysCallNo.sys_newstat, &sysStat);
    syscall.registerSysCall(syscall.SysCallNo.sys_lseek, &sysLSeek);
    syscall.registerSysCall(syscall.SysCallNo.sys_fcntl, &sysFCntl);
    syscall.registerSysCall(syscall.SysCallNo.sys_dup, &sysDup);
    syscall.registerSysCall(syscall.SysCallNo.sys_dup2, &sysDup2);
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

pub export fn sysMkDir(path: [*:0]const u8, mode:u16) callconv(std.builtin.CallingConvention.SysV) i64 {
    console.print("mkdir: {s}\n", .{path[0..std.mem.len(path)]});
    _=&mode;
    return 0;
}


pub export fn sysStat(path: [*:0]const u8, st:*Stat) callconv(std.builtin.CallingConvention.SysV) i64 {
    const len = std.mem.len(path);
    if (mounted_fs.ops.lookup(mounted_fs, path[0..len], 0)) |p| {
        defer mounted_fs.ops.free_path(mounted_fs, p);
        if (mounted_fs.ops.stat(mounted_fs, p, st)) |r| {
            return r;
        } else |_| {
            return -1;
        }
    } else |_| {
        return -1;
    }
}

pub export fn sysClose(fd:i64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const files = &task.getCurrentTask().fs.open_files;
    if (fd < 0 or fd >= files.items.len) {
        return -1;
    }
    if (files.items[@intCast(fd)]) |f| {
        f.put();
    } else {
        return -1;
    }
    return 0;
}
const F_DUPFD  =	0;
const F_DUPFD_CLOEXEC = 1030;

pub export fn sysDup(fd:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const cur = task.getCurrentTask();
    if (cur.fs.open_files.items[fd]) |f| {
        if (cur.fs.getFreeFd()) |f_| {
            if (f.get()) |ff| {
               cur.fs.installFd(f_, ff); 
                return @intCast(f_);
            }
        } else |_| {
            return -1;
        }
    }
    return -1;
}

pub export fn sysDup2(fd:u32, nfd:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const cur = task.getCurrentTask();
    if (nfd >= cur.fs.open_files.items.len) {
        if (cur.fs.ensureUnused(nfd + 1 - cur.fs.open_files.items.len)) {

        } else |_| {
            return -1;
        }
    }
    if (cur.fs.open_files.items[nfd]) |_| {
        return -1;
    }
    if (cur.fs.open_files.items[fd]) |f| {
        if (f.get()) |ff| {
           cur.fs.installFd(nfd, ff); 
            return nfd;
        }
    }
    return -1;
}
const F_GETFD=1;	
const F_SETFD=2;	
const F_GETFL=3;	
const F_SETFL=4;	
pub export fn sysFCntl(fd:u32, cmd:u32, arg:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    switch (cmd) {
    F_DUPFD, F_DUPFD_CLOEXEC => {
            const cur = task.getCurrentTask();
            const mfd:u32 = @intCast(arg);
            var nfd:i64 = -1;
            for (@min(mfd, cur.fs.open_files.items.len)..cur.fs.open_files.items.len) |i| {
                if (cur.fs.open_files.items[i] == null) {
                    nfd = @intCast(i);
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

// TEMP: move this out to console/tty 
const TIOCGPGRP = 0x540F;
const TIOCGWINSZ = 0x5413;
const TIOCSPGRP = 0x5410;
const WinSize = extern struct {
    rows:u16 align(1) = 0,
    cols:u16 align(1) = 0,
    xpixel:u16 align(1) = 0,
    ypixel:u16 align(1) = 0
};

pub export fn sysIoCtl(fd:u32, cmd:u32, arg:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    switch (cmd) {
        TIOCGPGRP => {
            const p:*u32 = @ptrFromInt(arg);
            p.* = 1;
        }, // TODO: fix this
        TIOCGWINSZ => {
            const p:*WinSize = @ptrFromInt(arg);
            p.rows = 25;
            p.cols = 40;
            p.xpixel = 16 * p.cols;
            p.ypixel = 16 * p.rows;
            return 0;
        },
        TIOCSPGRP => {
            _=&fd;
        },
        else => std.debug.panic("ioctl command not implemented: {}\n", .{cmd}),
    }
    _=&fd;
    _=&cmd;
    _=&arg;
    return 0;
}

const IoVec align(1) = extern struct {
    iov_base:?[*]u8,
    iov_len:usize
};

pub export fn sysReadV(fd:u32, vec:[*]IoVec, vlen:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    const fe = task.getCurrentTask().fs.open_files.items[fd];
    if (fe) |f| {
        var len:i64 = -1;
        for (0..vlen) |v| {
            const vp = &vec[v];
            if (vp.iov_base) |iov_base| {
                if (f.ops.read(f, iov_base[0..vp.iov_len])) |r| {
                    len = if (len == -1) @intCast(r.len) else len + @as(i64, @intCast(r.len));
                    f.pos += r.len;
                    if (r.len < vp.iov_len) {
                        break;
                    }
                } else |_| {
                    break;
                }
            }
        }
        return len;
    } else {
        return -1; // not opened
    }
}

pub export fn sysWriteV(fd:u32, vec:[*]IoVec, vlen:usize) callconv(std.builtin.CallingConvention.SysV) i64 {
    var len:i64 = -1;
    for (0..vlen) |i| {
        const v = &vec[i];
        if (v.iov_base) |vb| {
            const r = sysWrite(fd, vb, v.iov_len);
            if (r == -1) {
                break;
            }
            len = if (len == -1) r else len + r;
        }
    }
    return len;
}
// FIXME:
pub var fb_file:*File = undefined;

pub export fn sysOpen(path: [*:0]const u8, flags:u32, mode:u16) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const fde = t.fs.getFreeFd();
    if (fde) |fd| {
        // for testing fb
        const len = std.mem.len(path);
        if (std.mem.eql(u8, path[0..len], "/dev/fb")) {
             t.fs.installFd(fd, fb_file);
            return @intCast(fd);
        }
        const fe = mounted_fs.ops.lookup(mounted_fs, path[0..len], flags);
        if (fe) |f| {
            const file = File.get_new(f, f.fs.fops);
            if (file) |file_| {
                t.fs.installFd(fd, file_);
                var st:Stat = undefined;
                if (sysStat(path, &st) == 0) {
                    file_.size = st.st_size;
                }
                return @intCast(fd);
            } else |_| {
                f.fs.ops.free_path(f.fs, f);
                return -1;
            }
        } else |_| return -1;
    } else |_| return -1;

    _=&mode;
    return -1;
}

pub const SeekWhence = enum(u32) {
    set = 0,
    cur = 1,
    end = 2
};

pub export fn sysLSeek(fd: u32, off:i64, whence:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const fe = task.getCurrentTask().fs.open_files.items[fd];
    if (fe) |f| {
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
    } else {
        return -1; // not opened
    }
    return 0;

}

pub export fn sysRead(fd: u32, buf: [*]u8, len:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const fe = task.getCurrentTask().fs.open_files.items[fd];
    if (fe) |f| {
        if (f.ops.read(f, buf[0..len])) |r| {
            f.pos += r.len;
            return @intCast(r.len);
        } else |err| {
            return @intFromError(err);
        }
    } else {
        return -1; // not opened
    }
}

pub export fn sysWrite(fd: u32, buf: [*]u8, len:u64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const fe = task.getCurrentTask().fs.open_files.items[fd];
    if (fe) |f| {
        //TODO: fix this
        if (f.ops.write(f, buf[0..len])) |r| {
            return @intCast(r);
        } else |_| {
            return -1;
        }
    } else {
        return -1; // not opened
    }
}

