const std = @import("std");
const blk = @import("../block.zig");
const fs = @import("../../fs.zig");
const task = @import("../../task.zig");
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

const direct_blk:usize = 12;
var single_indirect_blk:usize = undefined;
var double_indirect_blk:usize = undefined;
var triple_indirect_blk:usize = undefined;
var entries_per_blk:u32 = undefined;

var bdev:*blk.BlockDevice = undefined;
var ext2fs:fs.MountedFs = undefined;
const ext2fs_ops = fs.FsOp {
    .lookup = &lookup,
    .lookupAt = &lookupAt,
    .copy_path = &copyPath,
    .free_path = &freePath,
    .stat = &stat,
};
const ext2fs_fops = fs.FileOps {
    .read = &read,
    .write = &write,
    .readdir = &readdir,
};

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

fn lookupAt(_:*fs.MountedFs, dir:fs.Path, name:[]const u8, flags:u32) anyerror!fs.Path {
    var d = try dir.copy();
    const e = try lookupDEntry(d.entry, name, flags);
    return d.append(e).*;
}

fn lookup(mfs:*fs.MountedFs, path:[]const u8, flags:u32) anyerror!fs.Path {
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
        const f = lookupDEntry(p.entry, e, flags) catch |err| {
            freePath(mfs, p);
            return err;
        };
        _ = p.append(f);
    }
    return p;
}

fn lookupDEntry(d:*fs.DirEntry, name:[]const u8, flags:u32) !*fs.DirEntry {
    _=flags;
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
    if (std.mem.eql(u8, n, ".")) return dupDirEntry(d);
    if (std.mem.eql(u8, n, "..")) {
        if (d.prev) |p| {
            return dupDirEntry(p);
        }
        return dupDirEntry(d);
    }
    return try getDirEnt(&inode, n);
}

fn freePath(_:*fs.MountedFs, path:fs.Path) void {
    var d:?*fs.DirEntry = path.entry;
    while (d) |r| {
        const p = r.prev;
        allocator.destroy(r);
        d = p;
    }
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
    var p = path;
    p.entry = try dupDirEntry(path.entry);
    var d:?*fs.DirEntry = path.entry;
    while (d) |e| {
        const dp = dupDirEntry(e) catch |err| {
            freePath(mfs, p);
            return err;
        };
        _=p.append(dp);
        d = e.next;
    }
    return p;
}

const bc = @import("../bcache.zig");

fn getBlockNumRange(n:*const INode, sbi:u64, ebi:u64, bkn:[]u64) !void {
    std.debug.assert(bkn.len == ebi - sbi);
    var i:usize = 0;
    var bcache = bc.BCache.new(bdev, block_size); 
    defer bcache.drop();

    for (sbi..ebi) |bi| {
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
    _=&file;
    _=&buf;
    return error.NotImplemented;
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
    const bkn = try allocator.alloc(u64, eblk - sblk);
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
    _ = try bdev.read(descriptor_offset, std.mem.asBytes(&bgd));
    return bgd;
}

fn readINode(inode_num: u32) !INode {
    const gi = (inode_num - 1) / super_block.inodes_per_group;
    const ii = (inode_num - 1) % super_block.inodes_per_group;
    const bgd = try readGroupDescriptor(gi);
    const inode_table_block = bgd.inode_table;
    const inode_table_start = inode_table_block * block_size;
    const offset = inode_table_start + ii * super_block.inode_size;

    var inode:INode = undefined;
    _ = try bdev.read(offset, std.mem.asBytes(&inode));
    return inode;
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

fn getDirEnt(inode:*const INode, ent_name:[]const u8) !*fs.DirEntry {
    var buf = try allocator.alloc(u8, block_size);
    defer allocator.free(buf);
    var i:usize = 0;
    while (true) {
        defer i+=1;
        if (i >= 12) {
            std.debug.panic("indirect blocks are not supported yet\n", .{});
            break;
        }
        const block_num = inode.block[i];
        if (block_num == 0) break;
        const block_offset = block_num * block_size;
        _ = try bdev.read(block_offset, buf);
        var pos: usize = 0;
        while (pos < block_size) {
            const entry = @as(*DirEntry, @ptrCast(&buf[pos]));
            if (entry.inode == 0) break;
            const name_ptr = @as([*]const u8, @ptrCast(&entry.name));
            const name = name_ptr[0..entry.name_len];
            pos += entry.rec_len;
            if (std.mem.eql(u8, name, ent_name)) {
                const pd = try DirEntObj.new(entry); 
                const r = allocator.create(fs.DirEntry) catch |err| {
                    obj.put(pd);
                    return err;
                };
                r.name = pd.name;
                switch (entry.file_type) {
                    @intFromEnum(EntType.EXT2_FT_DIR) => r.type = .DIR,
                    @intFromEnum(EntType.EXT2_FT_SYMLINK) => r.type = .LINK,
                    else => r.type = .FILE,
                }
                r.priv = pd;
                return r;
            }
        }
    }
    return error.FileNotFound;
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

    const bkn = try allocator.alloc(u64, eblk - sblk);
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
            if (entry.inode == 0) break;
            const name_ptr = @as([*]const u8, @ptrCast(&entry.name));
            const name = name_ptr[0..entry.name_len];
            const d_len = p_len + name.len + 1;
            const next = @as([*]u8, @ptrCast(dp)) + d_len;
            if (@as(u64, @intFromPtr(next)) > @as(u64, @intFromPtr(dend))) break :outer;
            pos += entry.rec_len;
            r_off += entry.rec_len;
            //if (std.mem.eql(u8, name, ".")
            //    or std.mem.eql(u8, name, "..")) {
            //    continue;
            //}
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
    poff.* = r_off;
    return ret;
}

const console = @import("../../console.zig");

