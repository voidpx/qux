const std = @import("std");
const blk = @import("../block.zig");
const fs = @import("../../fs.zig");
const task = @import("../../task.zig");
const bitset = @import("../../lib/bitset.zig");
const EXT2_SUPERBLOCK_OFFSET = 1024;
const EXT2_SUPER_MAGIC = 0xEF53;
var block_size:u32 = 1024; 
const type_mask:u16 = 0xf000;
const s_ifreg:u16 = 0x8000;
const s_ifdir:u16 = 0x4000;
const s_iflink:u16 = 0xa000;
const s_ifcdev:u16 = 0x2000;
const s_ifbdev:u16 = 0x6000;
const s_ifsk:u16 = 0x1000;
const s_iffifo:u16 = 0xc000;

const O_CREAT = 0o100;
const O_EXCL = 0o200;	
const O_NOCTTY=	0o400;
const O_TRUNC = 0o1000;
const O_APPEND=	0o2000;

const direct_blk:usize = 12;
var single_indirect_blk:usize = undefined;
var double_indirect_blk:usize = undefined;
var triple_indirect_blk:usize = undefined;
var entries_per_blk:u32 = undefined;

var n_groups:u32 = 0;

var bdev:*blk.BlockDevice = undefined;
var ext2fs:fs.MountedFs = undefined;
const ext2fs_ops = fs.FsOp {
    .lookup = &lookup,
    .lookupAt = &lookupAt,
    .mkdir = &mkdir,
    .rmdir = &rmdir,
    .unlink = &unlink,
    .copy_path = &copyPath,
    .free_path = &freePath,
    .stat = &stat,
};
const ext2fs_fops = fs.FileOps {
    .read = &read,
    .write = &write,
    .readdir = &readdir,
    .truncate = &truncate,
};

fn truncate(file:*fs.File) !void {
    const dent:*DirEntObj = @alignCast(@ptrCast(file.path.entry.priv));
    var inode = try readINode(dent.dentry.inode);
    if (inode.size > 0) {
        const sblk = 0;
        const eblk = (inode.size + block_size - 1) / block_size;
        const bkn = try allocator.alloc(u32, eblk - sblk);
        defer allocator.free(bkn);
        try getBlockNumRange(&inode, sblk, eblk, bkn);
        try freeBlocks(bkn);
        try freeINodeIndexBlocks(&inode);
    }
    inode.blocks = 0;
    inode.size = 0;
    inode.ctime = @intCast(time.getTime().sec);
    try writeINode(dent.dentry.inode, &inode);
}

fn unlink(mfs:*fs.MountedFs, dir:fs.Path, name:[]const u8) !void {
    const e = try lookupAt(mfs, dir, name, 0, 0);
    defer mfs.ops.free_path(mfs, e); 
    const dent:*DirEntObj = @alignCast(@ptrCast(e.entry.priv));
    var inode = try readINode(dent.dentry.inode);
    try unlinkINode(dent.dentry.inode, &inode);
    try removeDirEntry(dir.entry, name);
}

fn rmdir(mfs:*fs.MountedFs, path:[]const u8) anyerror!void {
    const p = try lookup(mfs, path, 0, 0);
    defer freePath(mfs, p);
    const dent:*DirEntObj = @alignCast(@ptrCast(p.entry.priv));
    if (dent.dentry.file_type != @intFromEnum(EntType.EXT2_FT_DIR)) {
        return error.NotDir;
    }
    unlink(mfs, p, "..") catch {};
    unlink(mfs, p, ".") catch {};
    const pdir = try p.getParent();
    defer freePath(mfs, pdir);
    try unlink(mfs, pdir, p.entry.name); 
}

fn removeDirEntry(dir:*fs.DirEntry, e_name:[]const u8) !void {
    const dent:*DirEntObj = @alignCast(@ptrCast(dir.priv));
    const dir_inode = try readINode(dent.dentry.inode);
    var buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    const total_blks = (dir_inode.size + block_size - 1) / block_size;
    for (0..total_blks) |i| {
        var bkn = [_]u32{0};
        try getBlockNumRange(&dir_inode, i, i+1, &bkn);
        const block_num = bkn[0];
        if (block_num == 0) continue;
        const block_offset = block_num * block_size;
        _ = try bdev.read(block_offset, buf);
        var pos: u32 = 0;
        while (pos < block_size) {
            const entry = @as(*DirEntry, @ptrCast(&buf[pos]));
            if (entry.inode != 0) {
                const name_ptr = @as([*]const u8, @ptrCast(&entry.name));
                const name = name_ptr[0..entry.name_len];
                if (std.mem.eql(u8, name, e_name)) {
                    entry.inode = 0; // make it unsed
                    _ = try bdev.write(block_offset, buf);
                    return;
                }
            }
            pos += entry.rec_len;
        }
    }
    return error.FileNotFound;
    
}

fn mkdir(mfs:*fs.MountedFs, dir:fs.Path, name:[]const u8, mode:u16) anyerror!void {
    const dent:*DirEntObj = @alignCast(@ptrCast(dir.entry.priv));
    var inode = try readINode(dent.dentry.inode);
    if (inode.mode & s_ifdir == 0) return error.InvalidDirectory;
    const e:?fs.Path = lookupAt(mfs, dir, name, 0, 0)
        catch blk:{break :blk null;};
    if (e) |et| {
        mfs.ops.free_path(mfs, et);
        return error.NameExist;
    }

    const new = try getOrCreateDirEnt(&inode, dent.dentry.inode, name, O_CREAT, 
        mode, null, EntType.EXT2_FT_DIR);
    const new_dir:*DirEntObj = @alignCast(@ptrCast(new.priv));
    var new_inode = try readINode(new_dir.dentry.inode);
    freeDirEntry(try getOrCreateDirEnt(&new_inode,  new_dir.dentry.inode, ".",
        O_CREAT, mode, new_dir.dentry.inode, EntType.EXT2_FT_DIR));
    new_inode.links_count+=1;
    try writeINode(new_dir.dentry.inode, &new_inode);

    freeDirEntry(try getOrCreateDirEnt(&new_inode,  new_dir.dentry.inode, "..", 
        O_CREAT, mode, dent.dentry.inode, EntType.EXT2_FT_DIR));
    inode.links_count += 1;
    try writeINode(dent.dentry.inode, &inode);

    freeDirEntry(new);
}

fn stat(_:*fs.MountedFs, path:fs.Path, s:*fs.Stat) anyerror!i64 {
    const d = path.entry;
    const dent:*DirEntObj = @alignCast(@ptrCast(d.priv));
    const ino = dent.dentry.inode; 
    const no = try readINode(ino);
    s.st_size = no.size;
    s.st_ino = ino;
    s.st_atime = no.atime;
    s.st_ctime = no.ctime;
    s.st_mtime = no.mtime;
    s.st_uid = no.uid;
    s.st_gid = no.gid;
    s.st_mode = no.mode;
    s.st_blocks = no.blocks;
    s.st_dev = 0;
    s.st_nlink = no.links_count;
    s.st_blksize = block_size;
    
    return 0;
}

fn readdir(file:*fs.File, d:*fs.DEntry, len:u64) !i64 {
    const dp:*DirEntObj = @alignCast(@ptrCast(file.path.entry.priv));  
    const inode = try readINode(dp.dentry.inode);
    const sz = try readDirEntries(&inode, &file.pos, d, len);
    return sz;
}

fn lookupAt(_:*fs.MountedFs, dir:fs.Path, name:[]const u8, flags:u32, mode:u16) anyerror!fs.Path {
    var d = try dir.copy();
    const e = try lookupDEntry(d.entry, name, flags, mode);
    return d.append(e).*;
}

fn lookup(mfs:*fs.MountedFs, path:[]const u8, flags:u32, mode:u16) anyerror!fs.Path {
    const cur = task.getCurrentTask().fs.cwd.?;
    if (path.len == 0) { // cwd
        return cur.copy();
    }
    var p:fs.Path = undefined;
    if (path[0] == '/') { // absolute path
        p = try mfs.root.copy();
    } else {
        p = try cur.copy();
    }
    var it = std.mem.splitSequence(u8, path, "/");
    while (it.next()) |e| {
        if (e.len == 0) continue;
        const f = lookupDEntry(p.entry, e, flags, mode) catch |err| {
            freePath(mfs, p);
            return err;
        };
        _ = p.append(f);
    }
    return p;
}

fn lookupDEntry(d:*fs.DirEntry, name:[]const u8, flags:u32, mode:u16) !*fs.DirEntry {
    var n = name;
    if (name.len == 0)
        return error.EmptyFileName;
    if (name[name.len - 1] == '/') { // trailing slash
        n = name[0..name.len - 1]; 
    }
    if (std.mem.startsWith(u8, name, "./")) {
        n = name[2..];
    }
    const dir:*DirEntObj = @alignCast(@ptrCast(d.priv));
    const inode = try readINode(dir.dentry.inode);
    if (!inode.isDir()) {
        return error.FileNotFound;
    }
    var f_type:EntType = .EXT2_FT_REG_FILE;
    if (mode & s_ifdir > 0) {
        f_type = .EXT2_FT_DIR;
    } // others
    const m:u16 = mode & ((@as(u16, 1) << 9) - 1);
    return try getOrCreateDirEnt(&inode, dir.dentry.inode, n, flags, m, null, f_type);
}

fn freePath(_:*fs.MountedFs, path:fs.Path) void {
    var d:?*fs.DirEntry = path.entry;
    while (d) |r| {
        const p = r.prev;
        freeDirEntry(r);
        d = p;
    }
}

fn freeDirEntry(d:*fs.DirEntry) void {
    const dp:*DirEntObj = @alignCast(@ptrCast(d.priv));
    obj.put(dp);
    allocator.destroy(d);
}

fn dupDirEntry(d:*fs.DirEntry) !*fs.DirEntry {
    const dp:*DirEntObj = @alignCast(@ptrCast(d.priv));
    const dd = try allocator.create(fs.DirEntry);
    dd.name = dp.name;
    dd.type = d.type;
    dd.priv = obj.get(dp);
    dd.prev = null;
    dd.next = null;
    return dd;
}

fn copyPath(mfs:*fs.MountedFs, path:fs.Path) anyerror!fs.Path {
    var n:?*fs.DirEntry = path.entry;
    var head:*fs.DirEntry = undefined;
    while (n) |e| {
        head = e;
        n = e.prev;
    }
    const nhead = try dupDirEntry(head);
    var p = fs.Path{.fs = mfs, .entry = nhead};
    errdefer freePath(mfs, p);
    n = head.next;
    while (n) |e| {
        _=p.append(try dupDirEntry(e));
        n = e.next;
    }
    return p;
}

const bc = @import("../bcache.zig");

fn getZeroBlock0() ![]u8 {
    const b = try allocator.alloc(u8, block_size);
    @memset(b, 0);
    return b;

}

fn getZeroBlock(block:*?[]u8) ![]u8 {
    return block.* orelse {
        block.* = try getZeroBlock0();
        return block.*.?;
    };
}

fn zeroDevBlock(blk_num:u32, zero_blk:*?[]u8) !void {
    const zeros = try getZeroBlock(zero_blk);
    _=try bdev.write(blk_num * block_size, zeros);
}

fn appendBlocks(n:*INode, ino:u32, blk_idx:u32, blks:u32, bkn:[]u32) !void {
    std.debug.assert(bkn.len >= blks);
    var bcache = bc.BCache.new(bdev, block_size); 
    defer bcache.drop();
    const gi = (ino - 1) / super_block.inodes_per_group;
    var zero_blk:?[]u8 = null;
    defer {
        if (zero_blk) |z| allocator.free(z);
    }
    var i:usize = 0;
    for (blk_idx..blk_idx + blks) |bi| {
        const nblk = try allocBlock(gi);
        defer {
            bkn[i] = nblk.blk_num;
            i+=1;
        }
        bkn[i] = nblk.blk_num;
        if (bi < direct_blk) {
            n.block[bi] = nblk.blk_num;
            continue;
        }
        if (bi < single_indirect_blk) {
            var block_num = n.block[direct_blk];
            if (block_num == 0) {
                const iblk = try allocBlock(gi);
                try zeroDevBlock(iblk.blk_num, &zero_blk);
                n.block[direct_blk] = iblk.blk_num;
                block_num = iblk.blk_num;
            }
            const ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(block_num)).ptr);
            ia[bi - direct_blk] = nblk.blk_num;
            _=try bdev.write(block_num * block_size, @as([*]const u8, @ptrCast(ia))[0..block_size]);
            continue;
        }
        if (bi < double_indirect_blk) {
            var block_num = n.block[direct_blk + 1];
            if (block_num == 0) {
                const iblk = try allocBlock(gi);
                try zeroDevBlock(iblk.blk_num, &zero_blk);
                n.block[direct_blk + 1] = iblk.blk_num;
                block_num = iblk.blk_num;
            }
            var ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(block_num)).ptr);
            var bii = (bi - single_indirect_blk)/entries_per_blk;
            const b1 = block_num;
            block_num = ia[bii];
            if (block_num == 0) {
                const iblk = try allocBlock(gi);
                try zeroDevBlock(iblk.blk_num, &zero_blk);
                ia[bii] = iblk.blk_num;
                _=try bdev.write(b1 * block_size, @as([*]const u8, @ptrCast(ia))[0..block_size]);
                block_num = iblk.blk_num;
            }
            ia = @ptrCast((try bcache.getBlock(block_num)).ptr);
            bii = (bi - single_indirect_blk) % entries_per_blk;
            ia[bii] = nblk.blk_num;
            _=try bdev.write(block_num * block_size, @as([*]const u8, @ptrCast(ia))[0..block_size]);
            continue;
        }
        if (bi < triple_indirect_blk) {
            var block_num = n.block[direct_blk + 2];
            if (block_num == 0) {
                const iblk = try allocBlock(gi);
                try zeroDevBlock(iblk.blk_num, &zero_blk);
                n.block[direct_blk + 2] = iblk.blk_num;
                block_num = iblk.blk_num;
            }
            var ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(block_num)).ptr);
            const epb2 = entries_per_blk*entries_per_blk;
            var bii = (bi - double_indirect_blk)/epb2;
            const b1 = block_num;
            block_num = ia[bii];
            if (block_num == 0) {
                const iblk = try allocBlock(gi);
                try zeroDevBlock(iblk.blk_num, &zero_blk);
                ia[bii] = iblk.blk_num;
                _=try bdev.write(b1 * block_size, @as([*]const u8, @ptrCast(ia))[0..block_size]);
                block_num = iblk.blk_num;
            }
            ia = @ptrCast((try bcache.getBlock(block_num)).ptr);
            const rem = (bi - double_indirect_blk) % epb2;
            bii = rem/entries_per_blk;
            const b2 = block_num;
            block_num = ia[bii];
            if (block_num == 0) {
                const iblk = try allocBlock(gi);
                try zeroDevBlock(iblk.blk_num, &zero_blk);
                ia[bii] = iblk.blk_num;
                _=try bdev.write(b2 * block_size, @as([*]const u8, @ptrCast(ia))[0..block_size]);
                block_num = iblk.blk_num;
            }
            ia = @ptrCast((try bcache.getBlock(block_num)).ptr);
            bii = rem%entries_per_blk;
            ia[bii] = nblk.blk_num;
            _=try bdev.write(block_num * block_size, @as([*]const u8, @ptrCast(ia))[0..block_size]);
            continue;
        }
    }
    n.blocks += (blks * block_size) >> 9;
    try writeINode(ino, n);
}

fn getBlockNumRange(n:*const INode, sbi:u64, ebi:u64, bkn:[]u32) !void {
    std.debug.assert(sbi <= ebi and bkn.len >= ebi - sbi);
    var i:usize = 0;
    var bcache = bc.BCache.new(bdev, block_size); 
    defer bcache.drop();

    const nblks = (n.size + block_size - 1) / block_size;
    var a_sbi = sbi;
    var a_ebi = ebi;
    if (sbi >= nblks) {
        a_sbi = 0;
        a_ebi = 0;
    }

    for (a_sbi..a_ebi) |bi| {
        defer {
            if (bkn[i] == 0) {
                std.debug.panic("bug\n", .{});
            }
            i+=1;
        }
        if (bi < direct_blk) {
            bkn[i] = n.block[bi];
            continue;
        }
        if (bi < single_indirect_blk) {
            const block_num = n.block[direct_blk];
            if (block_num == 0) return error.CorruptedFileSys;
            const ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(block_num)).ptr);
            bkn[i] = ia[bi - direct_blk];
            continue;
        }
        if (bi < double_indirect_blk) {
            var block_num = n.block[direct_blk + 1];
            if (block_num == 0) return error.CorruptedFileSys;
            var ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(block_num)).ptr);
            var bii = (bi - single_indirect_blk)/entries_per_blk;
            block_num = ia[bii];
            if (block_num == 0) return error.CorruptedFileSys;
            ia = @ptrCast((try bcache.getBlock(block_num)).ptr);
            bii = (bi - single_indirect_blk) % entries_per_blk;
            bkn[i] = ia[bii];
            continue;
        }
        if (bi < triple_indirect_blk) {
            var block_num = n.block[direct_blk + 2];
            if (block_num == 0) return error.CorruptedFileSys;
            var ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(block_num)).ptr);
            const epb2 = entries_per_blk*entries_per_blk;
            var bii = (bi - double_indirect_blk)/epb2;
            block_num = ia[bii];
            if (block_num == 0) return error.CorruptedFileSys;
            ia = @ptrCast((try bcache.getBlock(block_num)).ptr);
            const rem = (bi - double_indirect_blk) % epb2;
            bii = rem/entries_per_blk;
            block_num = ia[bii];
            if (block_num == 0) return error.CorruptedFileSys;
            ia = @ptrCast((try bcache.getBlock(block_num)).ptr);
            bii = rem%entries_per_blk;
            bkn[i] = ia[bii];
            continue;
        }
        return error.CorruptedFileSys;

    }
}

fn write(file:*fs.File, buf:[]const u8) anyerror!usize {
    var st:fs.Stat = undefined;
    if (try stat(file.path.fs, file.path, &st) != 0) return error.ErrorWriteFile;
    const len = file.pos + buf.len; 
    const sblk = file.pos / block_size;
    const eblk = (len + block_size - 1) / block_size;
    const dp:*DirEntObj = @alignCast(@ptrCast(file.path.entry.priv));  
    var inode = try readINode(dp.dentry.inode);
    const w_blks = eblk - sblk;
    const bkn = try allocator.alloc(u32, w_blks);
    defer allocator.free(bkn);
    if (st.st_size < len) {
        // allocate more blocks
        const ssblk = (st.st_size + block_size - 1) / block_size;
        const eeblk = (len + block_size - 1) / block_size;
        const nblks = eeblk - ssblk;
        if (nblks > 0) {
            try appendBlocks(&inode, dp.dentry.inode, @intCast(ssblk), @intCast(nblks), bkn);
        }
    }
    try getBlockNumRange(&inode, sblk, eblk, bkn);
    const foff = file.pos & ~(block_size);
    var woff:u32 = 0;
    for (0..w_blks) |i| {
        const b = bkn[i];
        var off:u32 = 0;
        var wlen:u32 = block_size;
        if (i == 0) {
            off = @intCast(foff);
            wlen -= @intCast(foff);
        }
        const left = buf.len - woff;
        wlen = @min(wlen, left);
        const boff = b * block_size + off;
        const end = woff + wlen;
        const ws = try bdev.write(boff, buf[woff..end]);
        std.debug.assert(ws == wlen);
        woff += wlen;
    }
    if (inode.size < len) {
        inode.size = @intCast(len);
    }

    const now = time.getTime().sec;
    inode.atime = @intCast(now);
    inode.mtime = @intCast(now);
    inode.ctime = @intCast(now);
    
    try writeINode(dp.dentry.inode, &inode);
    file.pos += buf.len;
    return buf.len;
}


fn read(file:*fs.File, buf:[]u8) ![]u8 {
    const dp:*DirEntObj = @alignCast(@ptrCast(file.path.entry.priv));  
    const inode = try readINode(dp.dentry.inode);
    if (file.pos >= inode.size) return buf[buf.len..];
    const sblk = file.pos / block_size;
    const off = file.pos % block_size;
    const rsz = @min(buf.len, inode.size - file.pos);
    const eblk = (file.pos + rsz + block_size - 1)/block_size;
    var si:usize = 0;
    const bkn = try allocator.alloc(u32, eblk - sblk);
    defer allocator.free(bkn);
    try getBlockNumRange(&inode, sblk, eblk, bkn);
    for (0..bkn.len) |i| {
        const bn = bkn[i];
        var offset:usize = 0;
        var len:usize = block_size;
        if (i == 0) {
            offset = off;
            len-=offset;
        }
        if (i == bkn.len - 1) {
            const rem = eblk * block_size - (file.pos + rsz);
            len -=  rem;
        }
        const readn = try bdev.read(bn * block_size + offset, buf[si..si+len]);
        if (readn != len) return error.CorruptedFileSys;
        si += len;
    }
    return buf[0..si];
}

pub fn init() void {
    bdev = blk.block_device.parts[0].?; // XXX: fisrt part has ext2 file system

    readSuperBlock(&super_block) catch unreachable;
    //console.print("SuperBlock Magic: {x}\n", .{super_block.magic});
    if (super_block.magic == EXT2_SUPER_MAGIC) {
        console.print("ext2 file system detected\n", .{});
    }

    block_size = @as(u32, 1024) << @as(u5, @truncate(super_block.log_block_size));
    entries_per_blk = block_size / @sizeOf(u32);
    single_indirect_blk = direct_blk + entries_per_blk;
    double_indirect_blk = single_indirect_blk + entries_per_blk * entries_per_blk;
    triple_indirect_blk = double_indirect_blk + entries_per_blk * entries_per_blk * entries_per_blk;

    n_groups = (super_block.blocks_count - super_block.first_data_block 
            + super_block.blocks_per_group - 1)/super_block.blocks_per_group;
    //const root_inode =  readINode(2) catch unreachable; 
    //listDir(&root, 0) catch unreachable;
    const root = allocator.alloc(u8, @sizeOf(DirEntry) + 1) catch unreachable;
    root[root.len - 1] = '/';
    const rd:*DirEntry = @ptrCast(root.ptr);
    rd.name_len = 1;
    rd.inode = 2;
    const root_dobj = DirEntObj.new(rd) catch unreachable;
    const root_dent = allocator.create(fs.DirEntry) catch unreachable;
    root_dent.name = root_dobj.name;
    root_dent.type = .DIR;
    root_dent.priv = root_dobj;
    root_dent.prev = null;
    root_dent.next = null;
    const root_path = fs.Path{.fs = &ext2fs, .entry = root_dent};  
    
    ext2fs = .{.root = root_path, .ctx = &super_block,
        .ops = &ext2fs_ops,
        .fops = &ext2fs_fops
    };
    fs.mounted_fs = &ext2fs;
}
const obj = @import("../../object.zig");
const DirEntObj = struct {
    dentry:DirEntry,
    name:[]const u8,
    fn new(d:*DirEntry) !*DirEntObj {
        const p = try obj.new(@This(), null, &dtor);
        const pn:[*]u8 = @ptrCast(&d.name);
        p.name = try copyName(pn[0..d.name_len]);
        p.dentry = d.*;
        return p;
    }
    fn copyName(name:[]u8) ![]u8 {
        const n = try allocator.alloc(u8, name.len);
        @memcpy(n, name);
        return n;
    }
    fn dtor(this:*@This()) void {
        allocator.free(this.name);
    }

    fn copy(this:*@This()) !*DirEntObj {
        const p = try obj.new(@This(), null, &dtor);
        p.name = try copyName(this.name);
        p.dentry = this.dentry;
        return p;
    }
};

const DirEntry = extern struct {
    inode: u32 align(1),
    rec_len: u16 align(1),
    name_len: u8,
    file_type: u8,
    name: [0]u8, // variable
};

const SuperBlock = extern struct {
    inodes_count: u32,
    blocks_count: u32,
    reserved_blocks_count: u32,
    free_blocks_count: u32,
    free_inodes_count: u32,
    first_data_block: u32,
    log_block_size: u32,
    log_fragment_size: u32,
    blocks_per_group: u32,
    fragments_per_group: u32,
    inodes_per_group: u32,
    mount_time: u32,
    write_time: u32,
    mount_count: u16,
    max_mount_count: u16,
    magic: u16,
    state: u16,
    errors: u16,
    minor_revision_level: u16,
    last_check: u32,
    check_interval: u32,
    creator_os: u32,
    revision_level: u32,
    default_reserved_user_id: u16,
    default_reserved_group_id: u16,

    // Extended Superblock fields (if revision_level > 0)
    first_inode: u32,
    inode_size: u16,
    block_group_number: u16,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    uuid: [16]u8,
    volume_name: [16]u8,
    last_mounted: [64]u8,
    algorithm_usage_bitmap: u32,

    // Performance hints
    prealloc_blocks: u8,
    prealloc_dir_blocks: u8,
    reserved_gdt_blocks: u16,

    // Journaling support (ext3/4, optional in ext2)
    journal_uuid: [16]u8,
    journal_inum: u32,
    journal_dev: u32,
    last_orphan: u32,

    hash_seed: [4]u32,
    def_hash_version: u8,
    journal_backup_type: u8,
    descriptor_size: u16,

    // Other fields
    default_mount_opts: u32,
    first_meta_block_group: u32,
    mkfs_time: u32,
    journal_blocks: [17]u32,

    // Reserved
    reserved: [172]u8, // Pad to make total size 1024 bytes
};

const INode = extern struct {
    mode: u16 align(1),                   // File mode
    uid: u16 align(1),                    // Low 16 bits of Owner UID
    size: u32 align(1),                   // Size in bytes
    atime: u32 align(1),                  // Last access time
    ctime: u32 align(1),                  // Creation time
    mtime: u32 align(1),                  // Last modification time
    dtime: u32 align(1),                  // Deletion time
    gid: u16 align(1),                    // Low 16 bits of Group ID
    links_count: u16 align(1),            // Hard link count
    blocks: u32 align(1),                 // Blocks count (in 512-byte sectors)
    flags: u32 align(1),                  // File flags
    osd1: u32 align(1),                   // OS-dependent 1 (e.g. reserved)

    block: [15]u32 align(1),              // Pointers to blocks
                                 // [0..11]  = direct blocks
                                 // [12]     = single indirect
                                 // [13]     = double indirect
                                 // [14]     = triple indirect

    generation: u32 align(1),             // File version (used by NFS)
    file_acl: u32 align(1),               // File ACL (extended attributes, optional)
    dir_acl_or_high_size: u32 align(1),   // Directory ACL (or high 32 bits of file size for large files)
    faddr: u32 align(1),                  // Fragment address (rarely used)

    osd2: [12]u8 align(1),                // OS-dependent 2 (padding/reserved or ext-specific fields)


    inline fn isDir(node:*const INode) bool {
        return (node.mode & type_mask) == s_ifdir;
    }

    inline fn isFile(node:*const INode) bool {
        return (node.mode & type_mask) == s_ifreg;
    }
};
const BlockGroupDescriptor = extern struct {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    free_blocks_count: u16,
    free_inodes_count: u16,
    used_dirs_count: u16,
    pad: u16,
    reserved: [12]u8,
};
var super_block:SuperBlock = undefined;

fn readSuperBlock(sbp:*SuperBlock) !void {
    const buf = std.mem.asBytes(sbp);
    _=try bdev.read(EXT2_SUPERBLOCK_OFFSET, buf);
    if (sbp.magic != EXT2_SUPER_MAGIC)
        return error.NotExt2;
}

fn readGroupDescriptor(gi:u32) !BlockGroupDescriptor {
    const descriptor_offset = if (block_size == 1024) 1024 else 4096 + gi * @sizeOf(BlockGroupDescriptor); 
    var bgd: BlockGroupDescriptor = undefined;
    const r = try bdev.read(descriptor_offset, std.mem.asBytes(&bgd));
    std.debug.assert(r == @sizeOf(BlockGroupDescriptor));
    return bgd;
}

fn readINode(inode_num: u32) !INode {
    const gi = (inode_num - 1) / super_block.inodes_per_group;
    const ii = (inode_num - 1) % super_block.inodes_per_group;
    const bgd = try readGroupDescriptor(gi);
    return readINodeInGrp(&bgd, ii);
}

fn readINodeInGrp(grp:*const BlockGroupDescriptor, idx_in_grp:u32) !INode {
    const inode_table_block = grp.inode_table;
    const inode_table_start = inode_table_block * block_size;
    const offset = inode_table_start + idx_in_grp * super_block.inode_size;
    var inode:INode = undefined;
    _ = try bdev.read(offset, std.mem.asBytes(&inode));
    return inode;

}

fn writeINode(inode_num: u32, inode:*INode) !void {
    const gi = (inode_num - 1) / super_block.inodes_per_group;
    const ii = (inode_num - 1) % super_block.inodes_per_group;
    const bgd = try readGroupDescriptor(gi);
    try writeINodeInGrp(&bgd, ii, inode);
}

fn writeINodeInGrp(grp:*const BlockGroupDescriptor, idx_in_grp:u32, inode:*INode) !void {
    const inode_table_block = grp.inode_table;
    const inode_table_start = inode_table_block * block_size;
    const offset = inode_table_start + idx_in_grp * super_block.inode_size;
    const w_len = try bdev.write(offset, std.mem.asBytes(inode));
    if (w_len != @sizeOf(INode)) {
        return error.ErrorSavingINode;
    }
}

const EntType = enum(u8) {
    EXT2_FT_UNKNOWN	   = 0,
    EXT2_FT_REG_FILE   = 1,
    EXT2_FT_DIR	   = 2,
    EXT2_FT_CHRDEV	   = 3,
    EXT2_FT_BLKDEV	   = 4,
    EXT2_FT_FIFO	   = 5,
    EXT2_FT_SOCK	   = 6,
    EXT2_FT_SYMLINK    = 7,
};

fn alignRecLen4(entry:*DirEntry) u32 {
    const sz:u32 = @sizeOf(DirEntry) + entry.name_len;
    return align4(sz);
}

fn align4(i:u32) u32 {
    return (i + 3) & ~@as(u32, 3);
}

fn getGroupIdx(ino:u32) u32 {
    return (ino - 1) / super_block.inodes_per_group;
}

fn getOrCreateDirEnt(dir_inode:*const INode, dir_ino:u32, ent_name:[]const u8, flags:u32,
    mode:u16, eino:?u32, etype:?EntType) !*fs.DirEntry {
    var buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    var gap_entry:?*DirEntry = null;
    var insert_blk:u32 = 0;
    var insert_off:u32 = 0;
    var insert_len:u16 = 0;
    const new_rec_len = align4(@truncate(@sizeOf(DirEntry) + ent_name.len));
    const total_blks = (dir_inode.size + block_size - 1) / block_size;
    for (0..total_blks) |i| {
        var bkn = [_]u32{0};
        try getBlockNumRange(dir_inode, i, i+1, &bkn);
        const block_num = bkn[0];
        if (block_num == 0) continue;
        const block_offset = block_num * block_size;
        _ = try bdev.read(block_offset, buf);
        var pos: u32 = 0;
        while (pos < block_size) {
            const entry = @as(*DirEntry, @ptrCast(&buf[pos]));
            if (entry.inode == 0) {
                if (gap_entry == null and insert_blk == 0 and entry.rec_len >= new_rec_len) {
                    insert_blk = block_num;
                    insert_off = pos;
                    insert_len = entry.rec_len;
                }
            } else {
                const name_ptr = @as([*]const u8, @ptrCast(&entry.name));
                const name = name_ptr[0..entry.name_len];
                const r_rec_len = alignRecLen4(entry);
                if (gap_entry == null and entry.rec_len - r_rec_len >= new_rec_len) {
                    insert_blk = block_num;
                    insert_off = pos + r_rec_len;
                    gap_entry = entry;
                }
                if (std.mem.eql(u8, name, ent_name)) {
                    return try newDirEntry(entry);
                }
            }
            pos += entry.rec_len;
        }
    }
    if (flags & O_CREAT > 0) { //O_CREAT
        const d = try createDirEntry(@constCast(dir_inode), dir_ino, buf, insert_blk, insert_off, insert_len, gap_entry,
            ent_name, eino, etype.?, mode);
        return try newDirEntry(d);
    }
    return error.FileNotFound;
}

fn newDirEntry(d:*DirEntry) !*fs.DirEntry {
    const pd = try DirEntObj.new(d); 
    errdefer obj.put(pd);
    const r = try allocator.create(fs.DirEntry) ;
    r.name = pd.name;
    switch (d.file_type) {
        @intFromEnum(EntType.EXT2_FT_DIR) => r.type = .DIR,
        @intFromEnum(EntType.EXT2_FT_SYMLINK) => r.type = .LINK,
        else => r.type = .FILE,
    }
    r.priv = pd;
    return r;
}

const time = @import("../../time.zig");
fn createDirEntry(dir:*INode, ino:u32, block:[]u8, insert_blk:u32, insert_off:u32, insert_len:u16, gap_entry:?*DirEntry,
    name:[]const u8, ent_ino:?u32, ft:EntType, mode:u16) !*DirEntry {
    var blk_num:u32 = insert_blk;
    var blk_off:u32 = insert_off; 
    var buf:[]u8 = block;
    const new_len = align4(@truncate(@sizeOf(DirEntry) + name.len));
    var entry:*DirEntry = undefined;
    if (insert_blk == 0) {
        // either the directory has no entries at all, or gap wasn't found to insert an entry, either way, a new block
        // has to be allocated
        var bkns = [_]u32{0};
        const index = (dir.size + block_size - 1) & ~(block_size - 1);
        try appendBlocks(dir, ino, index, 1, bkns[0..1]);
        blk_num = bkns[0];
        blk_off = 0;
        @memset(buf, 0); // zero out the block
        entry = @ptrCast(buf.ptr);
        entry.rec_len = @truncate(block_size);
        dir.size += block_size;
        dir.blocks += block_size >> 9;
        try writeINode(ino, dir);
    } else {
        entry = @ptrCast(&buf[insert_off]);
        if (gap_entry) |ge| {
            const e_len = alignRecLen4(ge);
            const gap_len = ge.rec_len - e_len;
            std.debug.assert(gap_len >= new_len);
            entry.rec_len = @intCast(gap_len);
            ge.rec_len = @intCast(e_len);
        } else if (insert_len > 0) {
            // found an empty entry that could hold this
            entry.rec_len = insert_len;
        } else {
            const left = block_size - insert_off;
            std.debug.assert(left >= new_len);
            entry.rec_len = @intCast(left);
        }
    }

    const gi = (ino - 1) / super_block.inodes_per_group;
    const e_ino = ent_ino orelse blk: {
        const an = (try allocINode(gi)).ino;
        const now = time.getTime().sec;
        var inode = std.mem.zeroes(INode);

        inode.mode = mode | (if (ft == .EXT2_FT_DIR) s_ifdir else s_ifreg);
        inode.atime = @intCast(now);
        inode.mtime = @intCast(now);
        inode.ctime = @intCast(now);
        inode.links_count = 1;
        // save the inode
        try writeINode(an, &inode);
        break :blk an;
    };

    entry.inode = e_ino;
    entry.file_type = @intFromEnum(ft);
    entry.name_len = @intCast(name.len);
    @memcpy(@as([*]u8, @ptrCast(&entry.name)), name);

    // save the entry
    _=try bdev.write(blk_num * block_size, buf);
    return entry;
}

const INodeAlloc = struct {
    group:BlockGroupDescriptor,
    ino:u32,
    inode:?*INode = null,
};

fn allocINode(start_gi:u32) !INodeAlloc {
    const buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    
    if (allocINodeFromGrp(start_gi, buf)) |r| {
        return r; // same group
    } else |_| {
        for (0..n_groups) |g| {
            if (g == start_gi) continue;
            return allocINodeFromGrp(@intCast(g), buf) catch continue;
        }
    }
    return error.OutOfSpace;
}

fn freeINodeIndexBlocks(inode:*INode) !void {
    var bcache = bc.BCache.new(bdev, block_size); 
    defer bcache.drop();
    const num:usize = block_size/@sizeOf(u32);
    for (0..inode.block.len) |i| {
        if (inode.block[i] == 0) break;
        switch (i) {
            0...11 => {
                // direct block 
            },
            12 => {
                try freeBlocks(&.{inode.block[i]});
            },
            13 => {
                const ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(inode.block[i])).ptr);
                var last:usize = num;
                for (0..num) |b| {
                    if (ia[b] == 0) {
                        last = b;
                        break;
                    }
                }
                try freeBlocks(ia[0..last]);
                try freeBlocks(&.{inode.block[i]});
            },
            14 => {
                const ia:[*] align(1) u32 = @ptrCast((try bcache.getBlock(inode.block[i])).ptr);
                var last:usize = num;
                for (0..num) |b| {
                    if (ia[b] == 0) {
                        last = b;
                        break;
                    }
                    const ian:[*] align(1) u32 = @ptrCast((try bcache.getBlock(ia[b])).ptr);
                    var lastn:usize = num;
                    for (0..num) |bn| {
                        if (ian[bn] == 0) {
                            lastn = bn;
                            break;
                        }
                    }
                    try freeBlocks(ian[0..lastn]);
                    try freeBlocks(&.{ia[b]});
                }
                try freeBlocks(ia[0..last]);
                try freeBlocks(&.{inode.block[i]});
            },
            else => {
                std.debug.panic("too many blocks ({}) for inode", .{i});
            }
        }
        inode.block[i] = 0;
    }
}

fn unlinkINode(ino:u32, inode:*INode) !void {
    // free blocks
    if (inode.links_count > 1) {
        inode.links_count -= 1;
        try writeINode(ino, inode);
        return;
    }
    if (inode.size > 0) {
        const sblk = 0;
        const eblk = (inode.size + block_size - 1) / block_size;
        const bkn = try allocator.alloc(u32, eblk - sblk);
        defer allocator.free(bkn);
        try getBlockNumRange(inode, sblk, eblk, bkn);
        try freeBlocks(bkn);
        try freeINodeIndexBlocks(inode);
    }
    const gi = (ino - 1) / super_block.inodes_per_group;
    const ii = (ino - 1) % super_block.inodes_per_group;
    var bgd = try readGroupDescriptor(gi);
    try freeINodeInGrp(&bgd, gi, ii);
}

fn freeINodeInGrp(grp:*BlockGroupDescriptor, gi:u32, idx_in_grp:u32) !void {
    const buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    const off = grp.inode_bitmap * block_size;
    _=try bdev.read(off, buf);
    var bs = bitset.bitSetFrom(buf);
    bs.unset(idx_in_grp);
    _=try bdev.write(off, buf); // update inode bitmap
    grp.free_inodes_count += 1;
    try writeBlockGroupDesc(gi, grp);

    super_block.free_inodes_count += 1;
    try writeSuperBlock(&super_block);
}

fn writeSuperBlock(sb:*SuperBlock) !void {
    const buf = std.mem.asBytes(sb);
    const len = try bdev.write(EXT2_SUPERBLOCK_OFFSET, buf);
    std.debug.assert(buf.len == len);
}

fn allocINodeFromGrp(g:u32, buf:[]u8) !INodeAlloc {
    var bgd = try readGroupDescriptor(g);
    if (bgd.free_inodes_count == 0) return error.NoFreeINode;
    const off = bgd.inode_bitmap * block_size;
    _=try bdev.read(off, buf);
    var bs = bitset.bitSetFrom(buf);
    const free = bitset.findFirstUnSet(&bs) orelse return error.NoFreeINode;
    bs.set(free);
    _=try bdev.write(off, buf); // update inode bitmap
    bgd.free_inodes_count -= 1;
    try writeBlockGroupDesc(g, &bgd);

    super_block.free_inodes_count -= 1;
    try writeSuperBlock(&super_block);
    const ino = free + g * super_block.inodes_per_group + 1;
    return INodeAlloc{.group = bgd, .ino = @intCast(ino)};
}

const BlockAlloc = struct {
    group:BlockGroupDescriptor,
    blk_num:u32,
};

fn allocBlock(start_gi:u32) !BlockAlloc {
    const buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    
    if (allocBlkFromGrp(start_gi, buf)) |r| {
        return r; // same group
    } else |_| {
        for (0..n_groups) |g| {
            if (g == start_gi) continue;
            return allocBlkFromGrp(@truncate(g), buf) catch continue;
        }
    }
    return error.OutOfSpace;
}

fn groupHasSb(gi:u32) bool {
    if (gi == 0) return true;
    var i = gi;
    while (i % 3 == 0) i /= 3;
    while (i % 5 == 0) i /= 5;
    while (i % 7 == 0) i /= 7;
    return i == 1;
}

fn writeBlockGroupDesc(g:u32, gd:*BlockGroupDescriptor) !void {
    // XXX: don't care about backup for now.
    //for (0..n_groups) |i| {
    //    
    //}
    const descriptor_offset = if (block_size == 1024) 1024 else 4096 + g * @sizeOf(BlockGroupDescriptor); 
    const len = try bdev.write(descriptor_offset, std.mem.asBytes(gd));
    std.debug.assert(len == @sizeOf(BlockGroupDescriptor));
}


fn freeBlocks(bkn:[]const align(1) u32) !void {
    const buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    const Array = std.ArrayList(u32);
    const GrpBlk = struct {
        bgd:BlockGroupDescriptor,
        blist:Array
    };
    const AutoMap = std.AutoHashMap(u32, GrpBlk);
    var map = AutoMap.init(allocator);

    defer {
        var vit = map.valueIterator();
        while (vit.next()) |n| {
            n.blist.deinit();
        }
        map.deinit();
    } 

    for (bkn) |b| {
        const g = b/super_block.blocks_per_group;
        var gd = map.get(g) orelse blk:{
            const bgd = try readGroupDescriptor(g);
            const blist = Array.init(allocator);
            const gb:GrpBlk = .{.bgd = bgd, .blist = blist};
            try map.put(g, gb);
            break :blk gb;
        };
        try gd.blist.append(b);

    }
    var it = map.iterator();
    while (it.next()) |n| {
        const g = n.key_ptr.*;
        const gb = n.value_ptr;
        const off = gb.bgd.block_bitmap * block_size;
        const r_len = try bdev.read(off, buf);
        std.debug.assert(r_len == buf.len);
        var bs = bitset.bitSetFrom(buf);
        for (gb.blist.items) |b| {
            const idx = b%super_block.blocks_per_group;
            bs.unset(idx);
        }
        _=try bdev.write(off, buf); // update inode bitmap
        gb.bgd.free_blocks_count += 1;
        try writeBlockGroupDesc(g, &gb.bgd);
        super_block.free_blocks_count += 1;
        try writeSuperBlock(&super_block);
    }

}

fn allocBlkFromGrp(g:u32, buf:[]u8) !BlockAlloc {
    var bgd = try readGroupDescriptor(g);
    if (bgd.free_blocks_count == 0) return error.NoFreeBlock;
    const off = bgd.block_bitmap * block_size;
    const r_len = try bdev.read(off, buf);
    std.debug.assert(r_len == buf.len);
    var bs = bitset.bitSetFrom(buf);
    const free = bitset.findFirstUnSet(&bs) orelse return error.NoFreeBlock;
    bs.set(free);
    _=try bdev.write(off, buf); // update inode bitmap
    bgd.free_blocks_count -= 1;
    try writeBlockGroupDesc(g, &bgd);
    super_block.free_blocks_count -= 1;
    try writeSuperBlock(&super_block);
    const blk_num = free + g * super_block.blocks_per_group;
    return BlockAlloc{.group = bgd, .blk_num = @truncate(blk_num)};

}

const allocator = @import("../../mem.zig").allocator;
fn readDirEntries(inode: *const INode, poff:*u64, d:*fs.DEntry, len:u64) !i64 {
    const off = poff.*;
    if (off >= inode.size) return 0;
    var buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);

    const end = @min(inode.size, off + len);
    const eblk = (end + block_size - 1)/block_size;

    const sblk = off / block_size;
    const blk_off = off % block_size;

    const bkn = try allocator.alloc(u32, eblk - sblk);
    defer allocator.free(bkn);
    try getBlockNumRange(inode, sblk, eblk, bkn);

    var i:usize = 0;
    var dp:*fs.DEntry = d;
    const dend:[*]u8 = @as([*]u8, @ptrCast(dp)) + len;
    var ret:i64 = 0;
    const p_len = @offsetOf(fs.DEntry, "d_name");
    var r_off:u64 = 0;
    outer:for (sblk..eblk) |bi| {
        defer i += 1;
        const b = bkn[i];
        const rlen = try bdev.read(b * block_size, buf);
        if (rlen != buf.len) return error.CorruptedFileSys;
        var pos = if (i == 0) blk_off else 0;
        const eoff = bi * block_size;
        while (pos < block_size) {
            const entry = @as(*DirEntry, @ptrCast(&buf[pos]));
            if (entry.inode == 0) {
                pos += entry.rec_len;
                r_off += entry.rec_len;
            } else {
                const name_ptr = @as([*]const u8, @ptrCast(&entry.name));
                const name = name_ptr[0..entry.name_len];
                const d_len = p_len + name.len + 1;
                const next = @as([*]u8, @ptrCast(dp)) + d_len;
                if (@as(u64, @intFromPtr(next)) > @as(u64, @intFromPtr(dend))) break :outer;
                pos += entry.rec_len;
                r_off += entry.rec_len;
                const namep:[*]u8 = @ptrCast(&dp.d_name);
                @memcpy(namep, name);
                namep[name.len] = 0;
                dp.d_ino = entry.inode;
                dp.d_off = @as(i64, @intCast(eoff)) + @as(i64, @intCast(pos));
                dp.d_type = entry.file_type;
                dp.d_reclen = @intCast(d_len);
                ret += @intCast(d_len);
                dp = @ptrCast(next);
            }
        }

    }
    poff.* += r_off;
    return ret;
}

const console = @import("../../console.zig");

