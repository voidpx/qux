const net = @import("net.zig");

const raw_sk_ops:net.SockOps = .{
    .bind = &bind,
    .listen = &listen,
    .accept = &accept,
    .connect = &connect,
    .send_to = &send_to,
    .send = &send,
    .recv_from = &recv_from,
    .recv = &recv,
    .release = &release,
};

fn bind(sk:*net.Sock, addr:*const net.SockAddr) anyerror!void {
    sk.src_addr = net.SockAddr{
        .family = 0,
        .port = @byteSwap(addr.port),
        .addr = @byteSwap(net.net_dev.ipv4_addr),
    };
}
fn listen(sk:*net.Sock) anyerror!void {
    _=&sk;
    return error.InvalidForRawProtocol;
}
fn accept(sk:*net.Sock) anyerror!*net.Sock {
    _=&sk;
    return error.InvalidForRawProtocol;
}
fn connect(sk:*net.Sock, addr:*const net.SockAddr) anyerror!void {
    _=&sk;
    _=&addr;
    return error.InvalidForRawProtocol;
}
fn send_to(sk:*net.Sock, buf:[]const u8, addr:?*const net.SockAddr) anyerror!usize{
    _=&addr;
    return send(sk, buf);
}
fn send(sk:*net.Sock, buf:[]const u8) anyerror!usize{

}
fn recv_from(sk:*net.Sock, buf:[]u8, addr:?*net.SockAddr) anyerror![]u8{
    _=&addr;
    return recv(sk, buf);
}
fn recv(sk:*net.Sock, buf:[]u8) anyerror![]u8{
}
fn release(sk:*net.Sock) void {
}

pub fn init() void {

}
