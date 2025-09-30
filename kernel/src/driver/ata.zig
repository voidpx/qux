const ATA_PRIMARY_IO:u16 = 0x1F0;
const ATA_PRIMARY_CTRL :u16 =   0x3F6;
const ATA_MASTER       :u8 =   0xE0;
const ATA_REG_DATA     :u16 =   (ATA_PRIMARY_IO + 0);
const ATA_REG_ERROR    :u16 =   (ATA_PRIMARY_IO + 1);
const ATA_REG_SECCOUNT0:u16 =   (ATA_PRIMARY_IO + 2);
const ATA_REG_LBA0     :u16 =   (ATA_PRIMARY_IO + 3);
const ATA_REG_LBA1     :u16 =   (ATA_PRIMARY_IO + 4);
const ATA_REG_LBA2     :u16 =   (ATA_PRIMARY_IO + 5);
const ATA_REG_HDDEVSEL :u16 =   (ATA_PRIMARY_IO + 6);
const ATA_REG_COMMAND  :u16 =   (ATA_PRIMARY_IO + 7);
const ATA_REG_STATUS :u16 = ATA_REG_COMMAND;
const ATA_REG_CONTROL  :u16 =   (ATA_PRIMARY_CTRL);

const ATA_CMD_READ_PIO_EXT:u8 = 0x24;
const ATA_CMD_IDENTIFY:u8 =     0xEC;

const ATA_CMD_WRITE_PIO_EXT:u8   = 0x34;
const ATA_CMD_CACHE_FLUSH_EXT:u8 = 0xEA;


const bytes_per_sector:u32 = 512;

var disk_capacity:u64 = 0;

const io = @import("../io.zig");
const std = @import("std");
const lock = @import("../lock.zig");

const blk = @import("block.zig");
fn ata_wait_busy() void {
    while ((io.in(u8, ATA_REG_STATUS) & 0x80) != 0) {}
}

fn ata_wait_drq() void {
    while ((io.in(u8, ATA_REG_STATUS) & 0x08) == 0) {}
}
fn readNoCheck(lba:u64, sector_count:u16, buffer:[]u16) io.IOError!void {
    std.debug.assert((sector_count << 8) == buffer.len);
    io.out(ATA_REG_HDDEVSEL, @as(u8, ATA_MASTER));
    ata_delay();
    // Send high bytes first (LBA48 requirement)
    io.out(ATA_REG_SECCOUNT0, @as(u8, @truncate(sector_count >> 8)));                     // sector count high byte
    io.out(ATA_REG_LBA0, @as(u8, @truncate((lba >> 24))));         // LBA bits 24-31
    io.out(ATA_REG_LBA1, @as(u8, @truncate((lba >> 32))));         // LBA bits 32-39
    io.out(ATA_REG_LBA2, @as(u8, @truncate((lba >> 40))));         // LBA bits 40-47

    io.out(ATA_REG_SECCOUNT0, @as(u8, @truncate(sector_count)));          // sector count low byte
    io.out(ATA_REG_LBA0, @as(u8, @truncate((lba >> 0))));          // LBA bits 0-7
    io.out(ATA_REG_LBA1, @as(u8, @truncate((lba >> 8))));          // LBA bits 8-15
    io.out(ATA_REG_LBA2, @as(u8, @truncate((lba >> 16))));         // LBA bits 16-23
    io.out(ATA_REG_COMMAND, ATA_CMD_READ_PIO_EXT);

    ata_wait_busy();
    for (0..sector_count) |i| {
        ata_wait_drq();
        const status = io.in(u8, ATA_REG_STATUS);
        if ((status & 0x01) != 0) {
            const err = io.in(u8, ATA_REG_ERROR);
            console.print("ATA Error: {x}\n", .{err});
            return io.IOError.ReadError;
        }
        if (status & 0x20 != 0) { // DF bit
            return io.IOError.ReadError;
        }
        const start = i << 8;
        for (0..256) |j| {
            buffer[start + j] = io.in(u16, ATA_REG_DATA);
        }

    }
}

fn ata_delay() void {
    _=io.in(u8, ATA_REG_STATUS); // status read = 400ns delay
    _=io.in(u8, ATA_REG_STATUS);
    _=io.in(u8, ATA_REG_STATUS);
    _=io.in(u8, ATA_REG_STATUS);
}

fn read(lba:u64, sector_count:u16, buffer:[]u16) io.IOError!void {
    if (capacity == 0 or lba + sector_count > capacity or buffer.len < (sector_count << 8)) return io.IOError.ReadError;
    try readNoCheck(lba, sector_count, buffer);
}

fn write(lba: u64, sector_count: u16, buffer: []u16) !void {
    std.debug.assert((sector_count << 8) == buffer.len); // 512 bytes per sector

    // Select master drive with LBA bit set
    io.out(ATA_REG_HDDEVSEL, ATA_MASTER);
    ata_delay();

    // Write high bytes first (LBA48 protocol)
    io.out(ATA_REG_SECCOUNT0, @as(u8, @truncate(sector_count >> 8)));
    io.out(ATA_REG_LBA0, @as(u8, @truncate(lba >> 24)));
    io.out(ATA_REG_LBA1, @as(u8, @truncate(lba >> 32)));
    io.out(ATA_REG_LBA2, @as(u8, @truncate(lba >> 40)));

    // Then write low bytes
    io.out(ATA_REG_SECCOUNT0, @as(u8, @truncate(sector_count)));
    io.out(ATA_REG_LBA0, @as(u8, @truncate(lba >> 0)));
    io.out(ATA_REG_LBA1, @as(u8, @truncate(lba >> 8)));
    io.out(ATA_REG_LBA2, @as(u8, @truncate(lba >> 16)));

    // Send write command
    io.out(ATA_REG_COMMAND, ATA_CMD_WRITE_PIO_EXT); // 0x34

    ata_wait_busy();
    for (0..sector_count) |i| {
        ata_wait_drq();
        const status = io.in(u8, ATA_REG_STATUS);
        if ((status & 0x01) != 0) {
            const err = io.in(u8, ATA_REG_ERROR);
            console.print("ATA Error: {x}\n", .{err});
            return io.IOError.WriteError;
        }
        if (status & 0x20 != 0) { // DF bit
            return io.IOError.WriteError;
        }
        const start = i << 8;
        for (0..256) |j| {
            const w = buffer[start + j];
            io.out(ATA_REG_DATA, w);
        }
    }
    ata_wait_busy();

    // Flush cache to ensure data hits disk
    io.out(ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH_EXT); // 0xEA
    ata_wait_busy();
}


var capacity:u32 = 0; // in sectors
pub fn init() void {
    // 1. Select primary master (0xA0 = master, 0xB0 = slave)
    io.out(ATA_REG_HDDEVSEL, ATA_MASTER);
    ata_delay();

    // 2. Send IDENTIFY command
    io.out(ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
    ata_delay();

    // 3. Read status
    var status:u8 = io.in(u8, ATA_REG_STATUS);
    if (status == 0) {
        // No device at all
        return;
    }

    // 4. Wait for BSY to clear and either DRQ or ERR to set
    while (status & 0x80 > 0) { // BSY
        status = io.in(u8, ATA_REG_STATUS);
    }

    if ((status & 0x01 > 0)) {
        // ERR bit set → device does not exist or not ATA
        return;
    }

    if (!(status & 0x08 > 0)) {
        // DRQ not set → not ready to transfer
        return;
    }

    // 5. Read IDENTIFY data (optional but confirms presence)
    var buf = [_]u16{0} ** 256;
    readNoCheck(0, 1, &buf) catch unreachable;
    for (0..256) |i| {
        //const w = buf[i];
        if (i == 100) {
            capacity = std.mem.bytesToValue(u32, &buf[i]); 
            console.print("disk capacity: 0x{x} sectors\n", .{ capacity });
        }
    }

    part_table = readPartTable();
    var bdev = blk.BlockDevice.new(null, capacity, &readBlks, &writeBlks);
    for (0..part_table.parts.len) |i| {
        if (part_table.parts[i].sectors > 0) {
            const p = part_table.parts[i];
            parts[i] = blk.BlockDevice.new(@as(*anyopaque, @ptrFromInt(p.start_lba)), p.sectors, &readBlks, &writeBlks);
            bdev.parts[i] = &parts[i];
        }
    }
    blk.block_device = bdev; 
    
    //test
    //var buf2 = [_]u16{0} ** 2048;
    //read(6680, 8, &buf2) catch unreachable;
    //read(2056, 1, &buf) catch unreachable;
    //read(2056, 1, &buf) catch unreachable;
    //read(2056, 1, &buf) catch unreachable;
    //read(2056, 1, &buf) catch unreachable;
}
var parts:[4]blk.BlockDevice = undefined;

fn readBlks(bdev:*blk.BlockDevice, start:usize, buf:[]u8) io.IOError!void {
    const l = lock.cli();
    defer lock.sti(l);
    var off:usize = 0;
    if (bdev.ctx) |c| {
        off = @intFromPtr(c); // partition start
    }
    off+=start;
    const blk_cnt = buf.len >> @as(u6, @truncate(bdev.blk_size_shift));
    if (off + blk_cnt > bdev.capacity) {
        return io.IOError.ReadError;
    }
    const buf2:[*]u16 align(1) = @alignCast(@ptrCast(buf.ptr));
    //XXX: handle blk_cnt >= 2^16 
    try read(off, @truncate(blk_cnt), buf2[0..buf.len/2]);
}

fn writeBlks(bdev:*blk.BlockDevice, start:usize, buf:[]const u8) io.IOError!void {
    const l = lock.cli();
    defer lock.sti(l);
    var off:usize = 0;
    if (bdev.ctx) |c| {
        off = @intFromPtr(c); // partition start
    }
    off+=start;
    const blk_cnt = buf.len >> @as(u6, @truncate(bdev.blk_size_shift));
    if (off + blk_cnt > bdev.capacity) {
        return io.IOError.ReadError;
    }
    const buf2:[*]u16 align(1) = @alignCast(@ptrCast(@constCast(buf.ptr)));
    //XXX: handle blk_cnt >= 2^16 
    try write(off, @truncate(blk_cnt), buf2[0..buf.len/2]);
}

var part_table:PartTable = undefined;
fn readPartTable() PartTable {
    var buf = [_]u16{0} ** 256;
    read(0, 1, &buf) catch unreachable;
    const bufb = @as([*]u8, @ptrCast(&buf));
    const pt = std.mem.bytesAsValue(PartTable, bufb + 0x1be);
    for (0..4) |i| {
        if (pt.parts[i].sectors > 0) {
            const pte = pt.parts[i];
            console.print("part {}: start: {}, size: {}, id: 0x{x}\n", .{i, pte.start_lba, pte.sectors, pte.sys_id});
        }
    }
    return pt.*;
}

pub const PartEntry = extern struct {
    bootable:u8,
    shead:u8,
    ssc: u16 align(1),
    sys_id:u8,
    ehead:u8,
    ecy:u16 align(1),
    start_lba:u32 align(1),
    sectors:u32 align(1),

};
const PartTable = struct {
    parts:[4]PartEntry 
};

const console = @import("../console.zig");

