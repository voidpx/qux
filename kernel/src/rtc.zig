const reg_second: u8 = 0x00 ;    // Seconds             0–59
const reg_minute: u8 = 0x02 ;    // Minutes             0–59
const reg_hour: u8 =  0x04;    //  Hours               0–23 in 24-hour mode, 
                             //  1–12 in 12-hour mode, highest bit set if pm
const reg_weekday: u8 =  0x06;    //  Weekday             1–7, Sunday = 1
const reg_day: u8 =  0x07;    //  Day of Month        1–31
const reg_month: u8 =  0x08;    //  Month               1–12
const reg_year: u8 =  0x09;    //  Year                0–99
const reg_century: u8 =  0x32;    //  Century (maybe)     19–20?
const reg_status_a: u8 =  0x0A;    //  Status Register A
const reg_status_b: u8 =  0x0B;    //  Status Register B

const cmos_addr: u16 = 0x70;
const cmos_data: u16 = 0x71;

const io = @import("io.zig");
const std = @import("std");
pub const RTC = extern struct {
    second:u8 = 0,
    minute:u8 = 0,
    hour:u8 = 0,
    weekday:u8 = 0,
    day:u8 = 0,
    month:u8 = 0,
    year:u16 = 0,
    pub fn toString(self: *const @This(), w: anytype) !void {
        try std.fmt.format(w, "{}-{}-{}T{}:{}:{}Z", .{self.year, self.month, self.day,
            self.hour, self.minute, self.second});
    }
};

fn isRTCUpdating() bool {
    io.out(cmos_addr, reg_status_a);
    return (io.in(u8, cmos_data) & 0x80) > 0;
}

fn readRTCReg(reg:u8) u8 {
    io.out(cmos_addr, reg);
    return io.in(u8, cmos_data);
}
pub fn readRTC() RTC {
    var rtc align(8) = RTC{};
    while (isRTCUpdating()) io.io_wait();
    rtc.second = readRTCReg(reg_second);
    rtc.minute = readRTCReg(reg_minute);
    rtc.hour = readRTCReg(reg_hour);
    rtc.weekday = readRTCReg(reg_weekday);
    rtc.day = readRTCReg(reg_day);
    rtc.month = readRTCReg(reg_month);
    rtc.year = readRTCReg(reg_year);
    while (true) {
        var rtc_last align(8) = rtc;
        while (isRTCUpdating()) io.io_wait();
        rtc.second = readRTCReg(reg_second);
        rtc.minute = readRTCReg(reg_minute);
        rtc.hour = readRTCReg(reg_hour);
        rtc.weekday = readRTCReg(reg_weekday);
        rtc.day = readRTCReg(reg_day);
        rtc.month = readRTCReg(reg_month);
        rtc.year = readRTCReg(reg_year);
        if (@as(*u64, @ptrCast(@alignCast(&rtc))).* == @as(*u64, @ptrCast(@alignCast(&rtc_last))).*) break;
    }
    const b = readRTCReg(reg_status_b);
    if ((b & 4) == 0) { // BCD
        rtc.second = bcdDecode(rtc.second); 
        rtc.minute = bcdDecode(rtc.minute); 
        rtc.hour = bcdDecode(rtc.hour & 0x7f) | (rtc.hour & 0x80);
        rtc.day = bcdDecode(rtc.day); 
        rtc.month = bcdDecode(rtc.month); 
        rtc.year = bcdDecode(@truncate(rtc.year));
    }
    if ((b & 2) == 0 and (rtc.hour & 0x80) > 0) {
        rtc.hour = ((rtc.hour & 0x7f) + 12) % 24; 
    }
    rtc.year = 2000 + rtc.year;
    return rtc;
}

inline fn bcdDecode(b: u8) u8 {
    return ((b&0xf0)>>1) + ((b&0xf0)>>3) + (b&0xf);
}



