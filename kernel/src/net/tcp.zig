
const TcpHdr = extern struct {
    sport:u16 align(1),
    dport:u16 align(1),
    seq:u32 align(1),
    ack:u32 align(1),
    hlen_res:u8 align(1),
    flags:u8 align(1),
    win_size:u16 align(1),
    csum:u16 align(1),
    urg:u16 align(1),
};

pub fn init() void {
}
