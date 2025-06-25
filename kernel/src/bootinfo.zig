/// must be aligned with the boot_info in head.c
pub const BootInfo = extern struct {
    mb2:u64,
    boot_pgd:u64,
    boot_pgd_size:u64,
    gdtr:u64,
    gdt:u64,

    pub fn getMb2(bi: *BootInfo) *Mb2 {
        return @ptrFromInt(bi.mb2);
    }
};

pub const Mb2Iter = struct {
    cur: *Tag,
    pub fn new(mb2: *Mb2) @This() {
        return .{.cur = @ptrFromInt(@intFromPtr(mb2) + @sizeOf(Mb2))};
    }
    pub fn next(i: *Mb2Iter) ?*Tag {
        if (i.cur.type == .mb2_tag_type_end) {
            return null;
        } else {
            const t = i.cur;
            i.cur = @ptrFromInt(@intFromPtr(t) + (t.size + 7) & ~@as(u32, 7));
            return t;
        }
    }
};

pub const Mb2 = extern struct {
    total_size: u32, 
    resv: u32 = 0,

    pub fn get(mb2: *Mb2, T:type, tag: TagType) ?*T {
        var it = Mb2Iter.new(mb2);
        while (it.next()) |t| {
            if (t.type == tag) {
                return @ptrCast(@alignCast(t));
            }
        }
        return null;
    }
};

const console = @import("console.zig");

pub fn init(b: *BootInfo) void { 
    //walkMbTags(@ptrFromInt(b.mb2), printTag); 
    const fb = b.getMb2().get(FrameBuffer, TagType.mb2_tag_type_framebuffer).?;
   // const fbc:*FrameBufferColor = @ptrFromInt(@as(u64, @intFromPtr(fb)) + @sizeOf(FrameBuffer));
   // const color = ((@as(u32, 1) << @truncate(fbc.framebuffer_blue_mask_size)) - 1) << @truncate(fbc.framebuffer_blue_field_position);

    for (0..fb.framebuffer_height) |i| {
        for (0..fb.framebuffer_width) |j| {
            const p = @as(*u32, @ptrFromInt(fb.framebuffer_addr + (j*4 + fb.framebuffer_pitch * i )));
            p.* = 0xffff;
        }
    }
}

fn printTag(t: *Tag) bool {
    console.print("tag: {s}, size: {d}\n", .{@tagName(t.type), t.size}); 
    return true;
}

pub fn walkMbTags(mb: *Mb2, f: fn(t: *Tag) bool) void {
    const size = mb.total_size;
    const end = @intFromPtr(mb) + size;
    var t = @intFromPtr(mb) + @sizeOf(Mb2);
    while (t < end) {
        const tag: *Tag = @ptrFromInt(t);
        if (!f(tag)) return;
        t += (tag.size + 7) & ~@as(u32, 7);
    }
}

pub const TagType = enum(u32) {
    mb2_tag_type_end = 0,
    mb2_tag_type_cmdline = 1,
    mb2_tag_type_boot_loader_name = 2,
    mb2_tag_type_module = 3,
    mb2_tag_type_basic_meminfo = 4,
    mb2_tag_type_bootdev = 5,
    mb2_tag_type_mmap = 6,
    mb2_tag_type_vbe = 7,
    mb2_tag_type_framebuffer = 8,
    mb2_tag_type_elf_sections = 9,
    mb2_tag_type_apm = 10,
    mb2_tag_type_efi32 = 11,
    mb2_tag_type_efi64 = 12,
    mb2_tag_type_smbios = 13,
    mb2_tag_type_acpi_old = 14,
    mb2_tag_type_acpi_new = 15,
    mb2_tag_type_network = 16,
    mb2_tag_type_efi_mmap = 17,
    mb2_tag_type_efi_bs = 18,
    mb2_tag_type_efi32_ih = 19,
    mb2_tag_type_efi64_ih = 20,
    mb2_tag_type_load_base_addr = 21,
};
pub const Color = extern struct {
    red: u8,
    green: u8,
    blue: u8,
};

pub const MemType = enum(u32) { 
    available = 1, 
    reserved, 
    acpi_reclaimable, 
    nvs, 
    bad 
};

pub const MemMapEntry = extern struct {
    addr: u64,
    len: u64,
    type: MemType,
    zero: u32,
};
//typedef struct mb2_mmap_entry multiboot_memory_map_t;

pub const Tag = extern struct {
    type: TagType,
    size: u32,
};

pub const String = extern struct {
    tag: Tag,
    //char string[0],
};

pub const Module = extern struct {
    tag: Tag,
    mod_start: u32,
    mod_end: u32,
    //char cmdline[0];
};

pub const BasicMemInfo = extern struct {
    tag: Tag,
    mem_lower: u32,
    mem_upper: u32,
};

pub const BootDev = extern struct {
    tag: Tag,
    biosdev: u32,
    slice: u32,
    part: u32,
};

pub const MemMap = extern struct {
    tag: Tag,
    entry_size: u32,
    entry_version: u32,
    //struct mb2_mmap_entry entries[0];
};

pub const VbeInfoBlock = extern struct { external_specification: [512]u8 };

pub const VbeModeInfoBlock = extern struct { external_specification: [256]u8 };

pub const Vbe = extern struct { tag: Tag, vbe_mode: u16, vbe_interface_seg: u16, vbe_interface_off: u16, vbe_interface_len: u16, vbe_control_info: VbeInfoBlock, vbe_mode_info: VbeModeInfoBlock };

pub const FrameBufferType = enum(u8) { indexed = 0, rgb, ega_text };

pub const FrameBuffer = extern struct { 
    tag: Tag, 
    framebuffer_addr: u64, 
    framebuffer_pitch: u32, 
    framebuffer_width: u32, 
    framebuffer_height: u32, 
    framebuffer_bpp: u8, 
    framebuffer_type: FrameBufferType,
    reserved: u16 };

pub const FrameBuffer_Palette = extern struct {
    num_colors: u16,

    // colors here
};

pub const FrameBufferColor = extern struct { 
    framebuffer_red_field_position: u8, 
    framebuffer_red_mask_size: u8, 
    framebuffer_green_field_position: u8, 
    framebuffer_green_mask_size: u8, 
    framebuffer_blue_field_position: u8, 
    framebuffer_blue_mask_size: u8 };

//const FrameBuffer = extern struct {
//    common: FrameBufferCommon,
//    color_info: union {
//        palette: struct {
//            framebuffer_palette_num_colors: u16,
//            //struct mb2_color framebuffer_palette[0];
//        },
//    },
//};

pub const ElfSections = extern struct {
    type: u32,
    size: u32,
    num: u32,
    entsize: u32,
    shndx: u32,
    //char sections[0];
};

pub const Apm = extern struct {
    type: u32,
    size: u32,
    version: u16,
    cseg: u16,
    offset: u16,
    cseg_16: u16,
    dseg: u16,
    flags: u16,
    cseg_len: u16,
    cseg_16_len: u16,
    dseg_len: u16,
};

pub const Efi32 = extern struct {
    type: u32,
    size: u32,
    pointer: u32,
};

pub const Efi64 = extern struct {
    type: u32,
    size: u32,
    pointer: u32,
};

pub const SmBios = extern struct {
    type: u32,
    size: u32,
    major: u8,
    minor: u8,
    reserved: [6]u8,
    //mb2_uint8_t tables[0];
};

pub const AcpiOld = extern struct {
    type: u32,
    size: u32,
    //mb2_uint8_t rsdp[0];
};

pub const AcpiNew = extern struct {
    type: u32,
    size: u32,
    //mb2_uint8_t rsdp[0];
};

pub const Network = extern struct {
    type: u32,
    size: u32,
    //mb2_uint8_t dhcpack[0];
};

pub const EfiMemMap = extern struct {
    type: u32,
    size: u32,
    descr_size: u32,
    descr_vers: u32,
    //mb2_uint8_t efi_mmap[0];
};

pub const Efi32_IH = extern struct {
    type: u32,
    size: u32,
    pointer: u32,
};

pub const Efi64_IH = extern struct {
    type: u32,
    size: u32,
    pointer: u64,
};

pub const LoadBaseAddr = extern struct {
    type: u32,
    size: u32,
    load_base_addr: u32,
};
