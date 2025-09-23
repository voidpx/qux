const std = @import("std");
const ip = @import("ip.zig");
const net = @import("net.zig");
const console = @import("../console.zig");
const TcpHdr = extern struct {
    sport:u16 align(1) = 0,
    dport:u16 align(1) = 0,
    seq:u32 align(1) = 0,
    ack:u32 align(1) = 0,
    hlen_res:u8 align(1) = 0b01010000,
    flags:u8 align(1) = 0,
    win_size:u16 align(1) = @byteSwap(@as(u16, 64240)),
    csum:u16 align(1) = 0,
    urg:u16 align(1) = 0,
    fn setSrcPort(self:*@This(), sp:u16) void {
         self.sport = @byteSwap(sp);
    }
    fn setDstPort(self:*@This(), dp:u16) void {
         self.dport = @byteSwap(dp);
    }
    fn setSum(self:*@This(), sum:u16) void {
         self.csum = @byteSwap(sum);
    }
    fn setSeq(self:*@This(), s:u32) void {
         self.seq = @byteSwap(s);
    }
    fn setAck(self:*@This(), a:u32) void {
         self.ack = @byteSwap(a);
    }
    fn setWinSize(self:*@This(), ws:u16) u16 {
         self.win_size = @byteSwap(ws);
    }
    fn setHdrLen(self:*@This(), nbytes:u8) void {
        const nw = nbytes/4;
         self.hlen_res = (nw & 0xf) << 4;
    }


    fn getSrcPort(self:*@This()) u16 {
        return @byteSwap(self.sport);
    }
    fn getDstPort(self:*@This()) u16 {
        return @byteSwap(self.dport);
    }
    fn getSum(self:*@This()) u16 {
        return @byteSwap(self.csum);
    }
    fn getSeq(self:*@This()) u32 {
        return @byteSwap(self.seq);
    }
    fn getAck(self:*@This()) u32 {
        return @byteSwap(self.ack);
    }
    fn getHdrLen(self:*@This()) u8 {
        return (self.h_len>>4) * 4;
    }
    fn getWinSize(self:*@This()) u16 {
        return @byteSwap(self.win_size);
    }

    fn isCWR(self:*@This()) bool {
        return self.getFlag(7);
    }
    fn isECE(self:*@This()) bool {
        return self.getFlag(6);
    }
    fn isURG(self:*@This()) bool {
        return self.getFlag(5);
    }
    fn isACK(self:*@This()) bool {
        return self.getFlag(4);
    }
    fn isPSH(self:*@This()) bool {
        return self.getFlag(3);
    }
    fn isRST(self:*@This()) bool {
        return self.getFlag(2);
    }
    fn isSYN(self:*@This()) bool {
        return self.getFlag(1);
    }
    fn isFIN(self:*@This()) bool {
        return self.getFlag(0);
    }

    fn getFlag(self:*@This(), shift:u3) bool {
        return self.flags & (@as(u8, 1) << shift) > 0;
    }
    fn setFlag(self:*@This(), shift:u3, set:bool) void {
        if (set) {
            self.flags |= @as(u8, 1) << shift;
        } else {
            self.flags &= ~(@as(u8, 1) << shift);
        }
    }
    fn setCWR(self:*@This(), f:bool) void {
        self.setFlag(7, f); 
    }
    fn setECE(self:*@This(), f:bool) void {
        self.setFlag(6, f); 
    }
    fn setURG(self:*@This(), f:bool) void {
        self.setFlag(5, f); 
    }
    fn setACK(self:*@This(), f:bool) void {
        self.setFlag(4, f); 
    }
    fn setPSH(self:*@This(), f:bool) void {
        self.setFlag(3, f); 
    }
    fn setRST(self:*@This(), f:bool) void {
        self.setFlag(2, f); 
    }
    fn setSYN(self:*@This(), f:bool) void {
        self.setFlag(1, f); 
    }
    fn setFIN(self:*@This(), f:bool) void {
        self.setFlag(0, f); 
    }

};

const TcpState = enum(u8) {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK,
    FIN_WAIT1,
    FIN_WAIT2,
    CLOSING,
    TIME_WAIT,
};

var recv:net.NetReceiver = .{.ctx = null, .recv = &tcpRecv};
pub fn init() void {
    ip.registerTransProto(net.TransProto.TCP, &recv) catch unreachable;
}

var state = TcpState.CLOSED;
var seq:u32 = 0;
var ack:u32 = 0;
const MSS:u16 = 1460;

fn calcTcpSum(p_sum:u16, pkt:*net.Packet) void {
    const data:[]u8 = pkt.getTransPacket();
    const thdr:*TcpHdr = @ptrCast(data.ptr);
    thdr.csum = 0;
    var sum = ip.calcSum(data);
    sum = ip.addToSumU16(sum, ~p_sum);
    thdr.setSum(sum);
}

fn tcpRecv(_:*net.NetReceiver, pkt:*net.Packet) !void {
    defer pkt.free();
    const th:*TcpHdr = @ptrCast(pkt.getTransPacket().ptr);
    const iph:*net.IpV4Hdr = pkt.getIpV4Hdr();
    //const iph:*net.IpV4Hdr = pkt.getIpV4Hdr();
    //console.print("tcp hdr:{any}\n", .{th});
    switch (state) {
        .CLOSED => {
            if (th.isSYN() and !th.isACK()) { // new connection
                const tcp_len = @sizeOf(TcpHdr) + 4;
                const out = try ip.newPacket(tcp_len);  // MSS
                const out_iph = out.getIpV4Hdr();
                const out_hdr:*TcpHdr = @ptrCast(out.getTransPacket().ptr);
                out_hdr.* = .{};
                out_hdr.setSrcPort(th.getDstPort());
                out_hdr.setDstPort(th.getSrcPort());
                out_hdr.setSeq(0);
                out_hdr.setAck(th.getSeq() + 1);
                out_hdr.setHdrLen(tcp_len);
                out_iph.setDstAddr(iph.getSrcAddr());
                out_iph.setTotalLen(@sizeOf(net.IpV4Hdr) + tcp_len); 
                out_iph.proto = @intFromEnum(net.TransProto.TCP);
                const opt_mss:[*]u8 = @as([*]u8, @ptrCast(out_hdr)) + @sizeOf(TcpHdr); 
                opt_mss[0] = 2;
                opt_mss[1] = 4;
                @as(*align(1) u16, @ptrCast(opt_mss+2)).* = @byteSwap(MSS);
                out_hdr.setACK(true);
                out_hdr.setSYN(true);
                try ip.ipSend(out, &calcTcpSum);
                state = .SYN_RCVD;
            }

        },
        .SYN_RCVD => {
            //connected:
            state = .ESTABLISHED;
        },
        else => {
            console.print("tcp packet:{s}\n", .{std.fmt.fmtSliceHexLower(pkt.getTransPacket())});
        }
    
    }
}



