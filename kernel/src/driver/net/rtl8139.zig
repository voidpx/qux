const lock = @import("../../lock.zig");
const net = @import("../../net/net.zig");
const arp = @import("../../net/arp.zig");
const idt = @import("../../idt.zig");
const pci = @import("../../pci.zig");
const rtl8139_vendro = 0x10ec;
const rtl8139_device = 0x8139;
const transmit_status: usize = 0x10;
const transmit_data: usize = 0x20;
const rbstart: usize = 0x30;
const command_register: usize = 0x37;
const capr: usize = 0x38;
const cbr: usize = 0x3a;
const interrupt_mask: usize = 0x3c;
const interrupt_status: usize = 0x3e;
const receive_config: usize = 0x44;
const transmit_config: usize = 0x40;
const config_0: usize = 0x51;
const config_1: usize = 0x52;
const media_status: usize = 0x58;
const config_3: usize = 0x59;
const config_4: usize = 0x5a;
const isr_rok:u16 = 0x1;
const isr_tok:u16 = 0x4;
const Rtl8139 = struct {
    pd:pci.PciDev,
    bar_addr:u64 = 0,
    bar_len:u64 = 0,
    recv_buf:[]u8 = undefined,
    x_state:[4]bool = .{true, true, true, true}, 
    x_index:u32 = 0,
    fn new(pci_dev:pci.PciDev) Rtl8139 {
        return .{.pd = pci_dev}; 
    }
};

const console = @import("../../console.zig");
var dev:Rtl8139 = undefined;
const net_dev_ops:net.NetDevOps = .{.read = &read, .write = &write};
var net_dev:net.NetDev = .{ .op = &net_dev_ops};
pub fn init() void {
    const rtl = pci.findDev(rtl8139_vendro, rtl8139_device) orelse {
        console.print("rtl8139 dev not found\n", .{}); 
        return;
    }; 
    dev = Rtl8139.new(rtl);
    const bars = dev.pd.getBar();
    for (0..bars.len) |i| {
        const b = bars[i] orelse continue;
        dev.bar_addr = b.addr;
        dev.bar_len = b.len;
        break;
    }
    const ptr:*u48 = @ptrFromInt(dev.bar_addr);
    const mac = ptr.*;
    net_dev.mac = @byteSwap(mac);
    // XXX: make this configurable
    net_dev.ipv4_addr = 0x6403a8c0; // 192.168.1.2
    //net_dev.ipv4_addr = 0x0a0a14ac; // 192.168.1.2
    console.print("mac: {x}:{x}:{x}:{x}:{x}:{x}\n", 
        .{@as(u8, @truncate(mac & 0xff)),
        @as(u8, @truncate((mac >> 8) & 0xff)),
        @as(u8, @truncate((mac >> 16) & 0xff)),
        @as(u8, @truncate((mac >> 24) & 0xff)),
        @as(u8, @truncate((mac >> 32) & 0xff)),
        @as(u8, @truncate((mac >> 40) & 0xff))});
    dev.pd.enableBusMastering();
    reset();
    initInterrupt();
    initRecv() catch unreachable;
    initXmit() catch unreachable;
    initCAPR() catch unreachable;
    net.registerNetDev(&net_dev);
}

fn orReg(reg:u64, val:anytype) !void {
    var v = readReg(reg, @TypeOf(val));
    v |= val;
    try writeRegAndCheck(reg, v);
}

const task = @import("../../task.zig");
fn interrupt(state:*idt.IntState) void {
    _=&state;
    const status =readReg(interrupt_status, u16);
    if (status == 0) return;
    if (status & isr_rok > 0) {
        task.wakeup(&net.net_rcv_wq);
    }
    writeReg(interrupt_status, @as(u16, 0b101));
}

fn readRecvBuf(ptr:[*]u8, pos:u16, buf:[]u8) u16 {
    const e = @addWithOverflow(pos, @as(u16, @truncate(buf.len)));
    if (e[1] != 0) {
        const s = buf.len-e[0];
        @memcpy(buf[0..s], ptr[pos..pos+s]); 
        @memcpy(buf[s..], ptr[0..e[0]]);
    } else {
        @memcpy(buf, ptr[pos..pos+buf.len]);
    }
    return e[0];
}

fn read(_:*net.NetDev) !?* align(1) net.Packet {
    const l = lock.cli();
    defer lock.sti(l);
    var capr_r = readReg(capr, u16);
    capr_r = @addWithOverflow(capr_r, 16)[0];
    const cbr_r = readReg(cbr, u16);
    if (capr_r == cbr_r) return null;
    var st:u16 = 0;
    capr_r = readRecvBuf(dev.recv_buf.ptr, capr_r, @as([*]u8, @ptrCast(&st))[0..2]);
    var length:u16 = 0;
    capr_r = readRecvBuf(dev.recv_buf.ptr, capr_r, @as([*]u8, @ptrCast(&length))[0..2]);
    const pkt = try net.Packet.new(length);
    capr_r = readRecvBuf(dev.recv_buf.ptr, capr_r, pkt.getRaw());
    capr_r = (capr_r + 3) & ~@as(u16, 0b11);
    capr_r = @subWithOverflow(capr_r, 16)[0];
    writeReg(capr, capr_r);
    return pkt;
}

fn _write(pkt:*net.Packet) !void {
    const l = lock.cli();
    defer lock.sti(l);
    const p = pkt.getRaw();
    const addr = mem.phyAddr(@intFromPtr(p.ptr));
    if (addr > 0xffffffff) {
        return error.InvalidDMAAddress;
    }
    while (true) {
        const i = dev.x_index;
        defer dev.x_index = (dev.x_index + 1) % 4;
        const off = i*4;
        const dp = transmit_data + off;
        const sp = transmit_status + off;
        var status = readReg(sp, u32);
        if (dev.x_state[i] or (status & (@as(u32, 0b11) << 14)) > 0) {
            writeReg(dp, @as(u32, @truncate(addr)));
            const len = @as(u12, @truncate(p.len)); 
            status &= ~((@as(u32, 1) << 12) - 1);
            status |= len;
            status &= ~(@as(u32, 1) << 13);
            if (dev.x_state[i]) dev.x_state[i] = false;
            writeReg(sp, status);
            status = readReg(sp, u32);

            //console.print("status after write:0x{x}\n", .{status});

            return;
        }

    }
}

fn write(ndev:*net.NetDev, pkt:*net.Packet) !void {
    pkt.setSrcMac(ndev.mac);
    if (pkt.getDstMac() == 0) {
        // arp resolve and send
        try arp.arpSend(ndev, pkt, &_write); 
    } else {
        // direct send
        try _write(pkt);
    }
}

const std = @import("std");
fn readPackets() void {
    var capr_r = readReg(capr, u16);
    while (true) {
        capr_r = @addWithOverflow(capr_r, 16)[0];
        const cbr_r = readReg(cbr, u16);
        if (capr_r == cbr_r) break;
        var st:u16 = 0;
        capr_r = readRecvBuf(dev.recv_buf.ptr, capr_r, @as([*]u8, @ptrCast(&st))[0..2]);
        var length:u16 = 0;
        capr_r = readRecvBuf(dev.recv_buf.ptr, capr_r, @as([*]u8, @ptrCast(&length))[0..2]);
        const buf = mem.allocator.alloc(u8, length) catch unreachable;
        capr_r = readRecvBuf(dev.recv_buf.ptr, capr_r, buf);
        
        console.print("{s}", .{std.fmt.fmtSliceHexLower(buf)});

        capr_r = (capr_r + 3) & ~@as(u16, 0b11);
        capr_r = @subWithOverflow(capr_r, 16)[0];
        writeReg(capr, capr_r);
    }
}

const pic = @import("../../pic.zig");
fn initInterrupt() void  {
    const i = dev.pd.getIrq();
    idt.registerIrq(i, &interrupt);
    writeReg(interrupt_mask, @as(u16, 0b101));
    pic.enable(i);
}

fn readReg(reg:u64, tp:type) tp {
    const p:*tp = @ptrFromInt(dev.bar_addr + reg);
    return p.*;
}

fn writeReg(reg:u64, val:anytype) void {
    const tp = @TypeOf(val);
    const p:*tp = @ptrFromInt(dev.bar_addr + reg);
    p.* = val;
}

fn writeRegAndCheck(reg:u64, val:anytype) !void {
    writeReg(reg, val);
    if (readReg(reg, @TypeOf(val)) != val) return error.ErrorWriting;
}

fn reset() void {
    writeReg(command_register, @as(u8, 0x10));
    while ((readReg(command_register, u8) & 0x10) != 0) {}
}

const mem = @import("../../mem.zig");
const recv_buf_size = 0x10000 + 16;
fn initRecv() !void {
    const rb = try mem.allocator.alloc(u8, recv_buf_size);
    dev.recv_buf = rb[0..recv_buf_size - 16];
    const addr = mem.phyAddr(@intFromPtr(rb.ptr));
    try writeRegAndCheck(rbstart, @as(u32, @truncate(addr))); 
    try orReg(receive_config, @as(u32, 0b1100010001010));
}

fn initCAPR() !void {
    try writeRegAndCheck(capr, @as(u16, 0xfff0));
}

fn initXmit() !void {
    // enable
    try orReg(command_register, @as(u8, 0b11) << 2);
    try orReg(transmit_config, @as(u32, 0b1) << 16);
}

inline fn turnOn() void {
    writeReg(config_1, @as(u8, 0));
}

