const io = @import("io.zig");
const PIC1:u16 = 0x20;
const PIC2:u16 = 0xA0;
const PIC1_DATA:u16 = PIC1 + 1;
const PIC2_DATA:u16 = PIC2 + 1;
const PIC_EOI:u8 = 0x20;

const ICW1_ICW4:u8	=0x01;		
const ICW1_SINGLE:u8	=0x02;	
const ICW1_INTERVAL4:u8	=0x04;	
const ICW1_LEVEL:u8	=0x08;	
const ICW1_INIT	:u8 =0x10;		
const ICW4_8086:u8	=0x01;		
const ICW4_AUTO:u8	=0x02;		
const ICW4_BUF_SLAVE:u8	=0x08;	
const ICW4_BUF_MASTER:u8	=0x0C;	
const ICW4_SFNM:u8	=0x10;
pub const OFFSET1:u8 = 0x20;
pub const OFFSET2:u8 = 0x28;

pub fn sendEOI(irq:u8) void {
    if(irq >= 8) {
        io.out( PIC2, PIC_EOI);
    }
    io.out(PIC1, PIC_EOI);
}

pub fn init() void {
    remap(OFFSET1, OFFSET2);
}

fn remap(offset1:u8, offset2:u8) void {
	
	io.out(PIC1, ICW1_INIT | ICW1_ICW4);  // starts the initialization sequence (in cascade mode)
	io.io_wait();
	io.out(PIC2, ICW1_INIT | ICW1_ICW4);
	io.io_wait();
	io.out(PIC1_DATA, offset1);                 // ICW2: Master PIC vector offset
	io.io_wait();
	io.out(PIC2_DATA, offset2);                 // ICW2: Slave PIC vector offset
	io.io_wait();
	io.out(PIC1_DATA, @as(u8, 4));                       // ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100)
	io.io_wait();
	io.out(PIC2_DATA, @as(u8, 2));                       // ICW3: tell Slave PIC its cascade identity (0000 0010)
	io.io_wait();
	
	io.out(PIC1_DATA, ICW4_8086);               // ICW4: have the PICs use 8086 mode (and not 8080 mode)
	io.io_wait();
	io.out(PIC2_DATA, ICW4_8086);
	io.io_wait();
	
	io.out(PIC1_DATA, @as(u8, 0xfb));   // restore saved masks.
	io.out(PIC2_DATA, @as(u8, 0xff));
}

pub fn enable(irq:u8) void {
    var r = irq;
    const port = if (r >= 8) blk: {r = r - 8; break: blk PIC2_DATA;} else PIC1_DATA;
    var a:u8 = io.in(u8, port);
    a &= ~(@as(u8, 1)<<@as(u3, @truncate(r)));
    io.out(port, a);
}

pub inline fn sti() void {
    asm volatile("sti");
}

pub inline fn cli() void {
    asm	volatile("cli");
}

    

