const k_map = @cImport({@cInclude("kmap.h");});
const lock = @import("lock.zig");
const console = @import("console.zig");
const fbcon = @import("ui/fbcon.zig");
const gdt = @import("gdt.zig");
const idt = @import("idt.zig");
pub const k_base: u64 = 0xffff800000000000;//k_map.KERNEL_BASE; //0xffff800000000000;
pub const k_page_map: u64 = 0xffffc00000000000;

pub const user_min:u64 = page_size;
pub const user_max:u64 = (@as(u64, 1)<<47) - page_size; // exclusive

pub const addr_mask: u64 = ~@as(u64, 0xffff000000000000);
pub const page_shift: u32 = 12;
pub const page_mask: u64 = (@as(u64, 1) << page_shift) - 1;

pub const page_size: u32 = 1 << page_shift;
const std = @import("std");
const bi = @import("bootinfo.zig");
var heap: u64 = undefined;
var used_pages: u64 = undefined;
/// only needed during init for the page bitmap
const InitAllocator = struct {
    const vt = std.mem.Allocator.VTable{ .alloc = &@This().alloc, .resize = &@This().resize, .remap = &@This().remap,
        .free = &@This().free };
    fn getAllocator() std.mem.Allocator {
        return std.mem.Allocator{ .ptr = @ptrCast(&heap), .vtable = &vt };
    }

    fn alloc(_: *anyopaque, len: usize, ptr_align: std.mem.Alignment, _: usize) ?[*]u8 {
        const aln:u8 = @intFromEnum(ptr_align);
        if (aln > 0) {
            heap = std.mem.alignForwardLog2(heap, aln);
        }
        const r = heap;
        heap += len;
        return @ptrFromInt(r);
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
        // init mem not freed!
    }
};

pub const allocator = _Allocator.getAllocator();
/// the main allocator for zig std lib
const _Allocator = struct {
    const vt = std.mem.Allocator.VTable{ .alloc = &@This().alloc, .resize = &@This().resize,
        .remap = &@This().remap, .free = &@This().free };
    fn getAllocator() std.mem.Allocator {
        return std.mem.Allocator{ .ptr = @ptrCast(@constCast(&vt)), .vtable = &vt };
    }

    fn alloc(_: *anyopaque, len: usize, ptr_align: std.mem.Alignment, _: usize) ?[*]u8 {
        const ret:[*]u8 = kmalloc(len, @intFromEnum(ptr_align)) catch return null;  
        //console.print("allocated: 0x{x}, size: 0x{x}\n", .{@as(u64, @intFromPtr(ret)), len});
        return ret;
    }
    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _=&ctx;
        _=&buf;
        _=&buf_align;
        _=&new_len;
        _=&ret_addr;
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(_: *anyopaque, buf: []u8, _: std.mem.Alignment, _: usize) void {
        kfree(buf);
        //console.print("freed: 0x{x}, size 0x{x}\n", .{@as(u64, @intFromPtr(buf.ptr)), buf.len});
    }
};

pub const PageType = enum(u8) { kernel = 0, pgt, user };

pub const Page = struct {
    const Self = @This();
    owner: ?*anyopaque = null,
    any: u64 = 0, // may be used for bitmap for pages managed by mcache
    type: PageType = .kernel,
    flag: u8 = 0,
    objs: u32 = 0,
    prev: ?*Self = null,
    next: ?*Self = null,
    //ref_count: std.atomic.Value(u64).init(0),
    pub fn getPhyAddr(p: *Self) u64 {
        const a = @intFromPtr(p);
        const pfn = (a - k_page_map) / @sizeOf(Self);
        return pfn << page_shift;
    }

    pub fn getVirAddr(p: *Self) u64 {
        return virtualAddr(p.getPhyAddr());
    }
};


pub inline fn virtualAddr(paddr: u64) u64 {
    return paddr + k_base;
}

pub inline fn phyAddr(vaddr: u64) u64 {
    return vaddr - k_base;
}
var max_pfn: u64 = 0;
var page_bitmap: std.DynamicBitSetUnmanaged = undefined;
pub var boot_info: *bi.Mb2 = undefined;

pub fn init(b: *bi.BootInfo) void {
    heap = @intFromPtr(@extern(*const u8, .{ .name = "_ebss" }));
    const mmap = b.getMb2().get(bi.MemMap, bi.TagType.mb2_tag_type_mmap).?;
    const count = (mmap.tag.size - 8) / mmap.entry_size;
    var p: [*]bi.MemMapEntry = @ptrFromInt(@intFromPtr(mmap) + @sizeOf(bi.MemMap));
    var j: u8 = 0;

    const max_ranges = 8;
    const MemRange = struct { start: u64, end: u64 };
    var mems = [_]?MemRange{null} ** max_ranges;
    for (0..count) |i| {
        const e = &p[i];
        if (e.type == .available) {
            if (j >= max_ranges) break;
            mems[j] = .{ .start = e.addr, .end = e.addr + e.len };
            console.print("memory: 0x{x}, size: 0x{x}\n", .{e.addr, e.addr + e.len});
            const pfn = mems[j].?.end >> page_shift;
            if (pfn > max_pfn) {
                max_pfn = pfn;
            }
            j += 1;
        }
    }

    const init_alloc = InitAllocator.getAllocator();
    page_bitmap = std.DynamicBitSetUnmanaged.initEmpty(init_alloc, max_pfn) catch unreachable;
    for (mems) |om| {
        const m = om orelse break;
        const spfn = std.mem.alignForwardLog2(m.start, page_shift) >> page_shift;
        const epfn = m.end >> page_shift;
        for (spfn..epfn) |i| {
            page_bitmap.set(i);
        }
    }

    // copy the boot info, as soon we won't have access to low memory
    const mb2 = b.getMb2();
    const mb2p = init_alloc.alloc(u8, mb2.total_size) catch unreachable;
    @memcpy(mb2p, @as([*]u8, @ptrFromInt(@intFromPtr(mb2))));
    boot_info = @as(*bi.Mb2, @ptrFromInt(@intFromPtr(mb2p.ptr)));

    initMCache();
    setupPageTable();
    //initPageTable();
    gdt.init();
    idt.init(); // reload idt after loading gdt?
    reserveKernelMem();

    //console.remap_console(@This());
    fbcon.remap();
    console.print("memory initalized\n", .{});
    console.inputInit();

    idt.registerExceptionHandler(0xe, &handlePageFault);

}

const task = @import("task.zig");
fn handlePageFault(state: *idt.IntState) void {
    const t = task.getCurrentTask();
    const cr2 = asm volatile("mov %cr2, %rax" : [cr2] "={rax}" (->u64));
    const cr3 = asm volatile("mov %cr3, %rax" : [cr3] "={rax}" (->u64));
    const cr4 = asm volatile("mov %cr4, %rax" : [cr4] "={rax}" (->u64));
    console.print("page fault: err code:{}, cr2:0x{x}, cr3:0x{x}, cr4:0x{x}, ip:0x{x}, task:{}\n", 
    .{state.err_code, cr2, cr3, cr4, state.rip, t.id});
    //std.debug.panic("page fault", .{});

    const l = lock.cli();
    defer lock.sti(l);

    const mm = t.mem;
    if (cr2 == 0) {
        std.debug.panic("trying to derefence null pointer\n", .{});
    }
    const v = mm.mmap(cr2, page_size, task.Mem.MAP_NOFT) catch |err| {
        console.print("error handling page fault, {any}\n", .{err});
        std.debug.panic("unable to handle page fault", .{});
    }; 
    console.print("page fault handled at, 0x{x}\n", .{v.start});
}

pub fn mapUserVm(pgd:*PageTable, start:u64, end:u64) !void {
    const l = lock.cli();
    defer lock.sti(l);
    const s = start & ~page_mask;
    const e = alignUp(end, page_shift);
    const pgs = (e >> page_shift) - (s >> page_shift);
    var a = s;
    for (0..pgs) |_| {
        const pgdi = pgdIdx(a);
        const pudi = pudIdx(a);
        const pmdi = pmdIdx(a);
        const ptei = pteIdx(a);
        if (pgd.entries[pgdi] == 0) {
            pgd.entries[pgdi] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        const pudp:*PageTable = @ptrFromInt(virtualAddr(pgd.entries[pgdi] & ~page_mask));
        if (pudp.entries[pudi] == 0) {
            pudp.entries[pudi] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        const pmdp:*PageTable = @ptrFromInt(virtualAddr(pudp.entries[pudi] & ~page_mask));
        if (pmdp.entries[pmdi] == 0) {
            pmdp.entries[pmdi] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        const ptep:*PageTable = @ptrFromInt(virtualAddr(pmdp.entries[pmdi] & ~page_mask));
        if (ptep.entries[ptei] == 0) {
            ptep.entries[ptei] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        a += page_size;
    }

}

pub fn dropUserMemRange(pgd: *PageTable, start:u64, end:u64) void {
    const v = lock.cli();
    defer lock.sti(v);
    var s = start & ~page_mask;
    const e = alignUp(end, page_shift);
    while (s < e) : (s += page_size) {
        const pgdi = pgdIdx(s);
        const pudi = pudIdx(s);
        const pmdi = pmdIdx(s);
        const ptei = pteIdx(s);
        if (pgd.entries[pgdi] == 0) {
            continue;
        }
        const pud:*PageTable = @ptrFromInt(virtualAddr(pgd.entries[pgdi] & ~page_mask));
        if (pud.entries[pudi] == 0) {
            continue;
        }
        const pmd:*PageTable = @ptrFromInt(virtualAddr(pud.entries[pudi] & ~page_mask));
        if (pmd.entries[pmdi] == 0) {
            continue;
        }
        var pte:*PageTable = @ptrFromInt(virtualAddr(pmd.entries[pmdi] & ~page_mask));
        if (pte.entries[ptei] == 0) {
            continue;
        }
        const pfn = pte.entries[ptei] >> page_shift;
        freePagesUnlocked(pfn2Page(pfn), 1);
        pte.entries[ptei] = 0;
    }
}

pub fn dropUserMem(pgd:*PageTable) void {
    const v = lock.cli();
    defer lock.sti(v);
    for (0..k_map_pgd_start) |i| {
        if (pgd.entries[i] == 0) {
            continue;
        }
        const pud:*PageTable = @ptrFromInt(virtualAddr(pgd.entries[i] & ~page_mask));
        for (0..pt_num) |j| {
            if (pud.entries[j] == 0) {
                continue;
            }
            const pmd:*PageTable = @ptrFromInt(virtualAddr(pud.entries[j] & ~page_mask));
            for (0..pt_num) |k| {
                if (pmd.entries[k] == 0) {
                    continue;
                }
                const pte:*PageTable = @ptrFromInt(virtualAddr(pmd.entries[k] & ~page_mask));
                for (0..pt_num) |n| {
                    if (pte.entries[n] == 0) {
                        continue;
                    }
                    const pfn = pte.entries[n] >> page_shift;
                    freePagesUnlocked(pfn2Page(pfn), 1);
                }
                freePagesUnlocked(pfn2Page(pmd.entries[k] >> page_shift), 1); 
            }
            freePagesUnlocked(pfn2Page(pud.entries[j] >> page_shift), 1); 
        }
        freePagesUnlocked(pfn2Page(pgd.entries[i] >> page_shift), 1); 
    }
    freePagesUnlocked(pfn2Page(phyAddr(@intFromPtr(pgd)) >> page_shift), 1); 
}

fn allocPgtUnlocked() !*PageTable {
    const p = try allocPagesUnlocked(1);
    const ret:*PageTable = @ptrFromInt(p.getVirAddr());
    zeroPageTable(ret[0..1]);
    return ret;
}

pub fn clonePageTable(pgd: *PageTable) !*PageTable {
    const v = lock.cli();
    defer lock.sti(v);
    const new_pgd:*PageTable = try allocPgtUnlocked();
    @memcpy(@as(*[1]PageTable, new_pgd), @as(*[1]PageTable, pgd));
    for (0..k_map_pgd_start) |i| {
        const pud = pgd.entries[i];
        if (pud != 0) {
            const pudp:*PageTable = @ptrFromInt(virtualAddr(pud & ~page_mask));
            const new_pud:*PageTable = try allocPgtUnlocked();
            @memcpy(@as(*[1]PageTable, new_pud), @as(*[1]PageTable, pudp));
            new_pgd.entries[i] = phyAddr(@intFromPtr(new_pud)) | (pud & page_mask);
            for (0..pt_num) |j| {
               const pmd = pudp.entries[j];
                if (pmd != 0) {
                    const pmdp:*PageTable = @ptrFromInt(virtualAddr(pmd & ~page_mask));
                    const new_pmd:*PageTable = try allocPgtUnlocked();
                    @memcpy(@as(*[1]PageTable, new_pmd), @as(*[1]PageTable, pmdp));
                    new_pud.entries[j] = phyAddr(@intFromPtr(new_pmd)) | (pmd & page_mask);
                    for (0..pt_num) |k| {
                        const pte = pmdp.entries[k];
                        if (pte != 0) {
                            const ptep:*PageTable = @ptrFromInt(virtualAddr(pte & ~page_mask));
                            const new_pte:*PageTable = try allocPgtUnlocked();
                            @memcpy(@as(*[1]PageTable, new_pte), @as(*[1]PageTable, ptep));
                            new_pmd.entries[k] = phyAddr(@intFromPtr(new_pte)) | (pte & page_mask);
                            for (0..pt_num) |n| {
                                const pga = ptep.entries[n];
                                if (pga != 0) {
                                    const pgap:*PageTable = @ptrFromInt(virtualAddr(pga & ~page_mask));
                                    const new_pga:*PageTable = try allocPgtUnlocked(); // real address, use PageTable for copy
                                    @memcpy(@as(*[1]PageTable, new_pga), @as(*[1]PageTable, pgap));
                                    new_pte.entries[n] = phyAddr(@intFromPtr(new_pga)) | (pga & page_mask);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return new_pgd;
}

pub fn newPGD() !*PageTable {
    const l = lock.cli();
    defer lock.sti(l);
    var pgd:*PageTable = try allocPgtUnlocked();
    @memcpy(pgd.entries[k_map_pgd_start..pt_num], @as(*PageTable, @ptrFromInt(k_pgd)).entries[k_map_pgd_start..pt_num]);
    return pgd;
}

pub var k_pgd: u64 = 0;
const pt_num = 512;
pub const PageTable = extern struct { 
    entries: [pt_num]u64, 
    pub fn new() !*PageTable {
        return newPGD();
    }
    pub fn drop(p:*@This()) void {
        freePages(pfn2Page(phyAddr(@intFromPtr(p)) >> page_shift), 1); 
    }
};
const k_map_pgd_start = pgdIdx(k_base);

fn reserveKernelMem() void {
    var count:u64 = 0;
    for (0..0x100000>>page_shift) |i| { // reserve 0-1M
        page_bitmap.unset(i);
        count += 1;
    }
    const k_start: u64 = @intFromPtr(@extern(*const u8, .{ .name = "_stext" }));
    const k_end = std.mem.alignForwardLog2(heap, page_shift);
    const spfn = phyAddr(k_start) >> page_shift;
    const epfn = phyAddr(k_end) >> page_shift;
    for (spfn..epfn) |i| {
        page_bitmap.unset(i);
        count += 1;
    }
    const k_stack: u64 = @intFromPtr(@extern(*const u8, .{ .name = "_init_stack" }));
    const k_stack_end: u64 = @intFromPtr(@extern(*const u8, .{ .name = "_init_stack_end" }));
    const stack_pfn = phyAddr(k_stack) >> page_shift;
    const stack_pfn_end = stack_pfn + ((k_stack_end - k_stack) >> page_shift);
    for (stack_pfn..stack_pfn_end) |i| {
        page_bitmap.unset(i);
        count += 1;
    }
    used_pages = count;
}

const pgd_shift: u32 = 39;
const pgd_mask: u64 = (@as(u64, 1) << pgd_shift) - 1;
const pud_shift: u32 = 30;
const pud_mask: u64 = (@as(u64, 1) << pud_shift) - 1;
const pmd_shift: u32 = 21;
const pmd_mask: u64 = (@as(u64, 1) << pmd_shift) - 1;
inline fn pgdIdx(addr: u64) u64 {
    return (addr & addr_mask) >> pgd_shift;
}

inline fn pudIdx(addr: u64) u64 {
    return (addr & pgd_mask) >> pud_shift;
}

inline fn pmdIdx(addr: u64) u64 {
    return (addr & pud_mask) >> pmd_shift;
}

inline fn pteIdx(addr: u64) u64 {
    return (addr & pmd_mask) >> page_shift;
}

pub const MemoryError = error{OutOfMemory, InvalidMemory};

const PtPageCount = [3]u32;

const PageMapPages = struct {
    pud_pages: u32 = 0,
    pmd_pages: u32 = 0,
    pte_pages: u32 = 0
};

fn calcPtPages(start:u64, end:u64) PageMapPages {
    const spte = (start & addr_mask) >> page_shift;
    const epte = alignUp(end & addr_mask, page_shift) >> page_shift;
    const spme = spte >> 9;
    const epme = alignUp(epte, 9) >> 9;
    const pte_pages = epme - spme;
    const spue = spme >> 9;
    const epue = alignUp(epme, 9) >> 9;
    const pme_pages = epue - spue;
    const spge = spue >> 9;
    const epge = alignUp(epue, 9) >> 9;
    const pue_pages = epge - spge;
    return .{.pud_pages = @truncate(pue_pages), .pmd_pages = @truncate(pme_pages), .pte_pages = @truncate(pte_pages)};
}

pub const alignUp = std.mem.alignForwardLog2;

test "test calc pt pages" {
    const r = calcPtPages(k_base, k_base + 0x80000001);
    std.debug.print("r: {}, {}, {}\n", .{r.pud_pages, r.pmd_pages, r.pte_pages});
}

fn populate_ptb(tb:[]PageTable, s:u64, next_level:[]PageTable) void {
    std.debug.assert(s < pt_num);
    var n = s;
    var pi:u64 = 0;
    for (0..tb.len) |i| {
        var t = &tb[i];
        for (pi..next_level.len) |j| {
            t.entries[n] = phyAddr(@intFromPtr(&next_level[j])) | 0x7;
            n += 1;
            pi = j+1;
            if (n == pt_num) {
                n = 0;
                break;
            }
        }
    }
}

fn zeroPageTable(t:[]PageTable) void {
    for (t) |*tb| {
        @memset(@as(*[pt_num]u64, @ptrCast(tb)), 0);
    }
}

// map vm for kernel, never released, used after page mapping has been setup, with interrupt disabled
pub fn kernelMapVm(start:u64, end:u64, spfn:u64) !void {
    const pgd:*PageTable = @ptrFromInt(k_pgd);
    const s = start & ~page_mask;
    const e = alignUp(end, page_shift);
    const pgs = (e >> page_shift) - (s >> page_shift);
    var a = s;
    var pfn = spfn;
    for (0..pgs) |_| {
        const pgdi = pgdIdx(a);
        const pudi = pudIdx(a);
        const pmdi = pmdIdx(a);
        const ptei = pteIdx(a);
        if (pgd.entries[pgdi] == 0) {
            pgd.entries[pgdi] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        const pudp:*PageTable = @ptrFromInt(virtualAddr(pgd.entries[pgdi] & ~page_mask));
        if (pudp.entries[pudi] == 0) {
            pudp.entries[pudi] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        const pmdp:*PageTable = @ptrFromInt(virtualAddr(pudp.entries[pudi] & ~page_mask));
        if (pmdp.entries[pmdi] == 0) {
            pmdp.entries[pmdi] = phyAddr(@intFromPtr(try allocPgtUnlocked())) | 0x7;
        }
        const ptep:*PageTable = @ptrFromInt(virtualAddr(pmdp.entries[pmdi] & ~page_mask));
        if (ptep.entries[ptei] == 0) {
            ptep.entries[ptei] = (pfn << page_shift) | 0x103;
        }
        a += page_size;
        pfn += 1;
    }
}

// early map vm, e.g. bootstrap, before page mapping setup
fn initMapVm(start:u64, end:u64, pgd:*PageTable, spfn:u64) void {
    const pmp = calcPtPages(start, end);
    const npfn = (alignUp(end, page_shift) >> page_shift) - (start >> page_shift);
    heap = alignUp(heap, page_shift);
    const pud:[*]PageTable = @ptrFromInt(heap);
    const pmd:[*]PageTable = pud + pmp.pud_pages;
    const pte:[*]PageTable = pmd + pmp.pmd_pages;
    heap = @intFromPtr(pte + pmp.pte_pages);
    zeroPageTable(pud[0..pmp.pud_pages + pmp.pmd_pages + pmp.pte_pages]);
    populate_ptb(pgd[0..1], pgdIdx(start), pud[0..pmp.pud_pages]);
    populate_ptb(pud[0..pmp.pud_pages], pudIdx(start), pmd[0..pmp.pmd_pages]);
    populate_ptb(pmd[0..pmp.pmd_pages], pmdIdx(start), pte[0..pmp.pte_pages]);
    var n = pteIdx(start);
    var pi:u64 = 0;
    for (0..pmp.pte_pages) |i| {
        var p = &pte[i];
        for (pi..npfn) |j| {
            p.entries[n] = ((spfn + j) << page_shift) | 0x103;
            n += 1;
            pi = j+1;
            if (n==pt_num) {
                n = 0;
                break;
            }
        }
    }
}

fn setupPageTable() void {
    k_pgd = alignUp(heap, page_shift); // global page directory
    heap += page_size;
    zeroPageTable(@as([*]PageTable, @ptrFromInt(k_pgd))[0..1]);
    // map all physical memory, XXX: optimize? 
    initMapVm(k_base, k_base+(max_pfn << page_shift), @ptrFromInt(k_pgd), 0);
    const pm_pages = alignUp(max_pfn * @sizeOf(Page), page_shift) >> page_shift;
    heap = alignUp(heap, page_shift);
    const pm_pfn = phyAddr(heap) >> page_shift;
    heap += (pm_pages << page_shift);
    initMapVm(k_page_map, k_page_map + (pm_pages << page_shift), @ptrFromInt(k_pgd), pm_pfn); 

    loadCR3(k_pgd);
}

pub inline fn loadCR3(pgd: u64) void {
    const cr3 = phyAddr(pgd);
    asm volatile (
        \\
        \\ mov %rax, %cr3
        \\
        :
        : [cr3] "{rax}" (cr3),
    );
}

fn initMCache() void {
    mem_caches.ptr = @ptrFromInt(heap);
    mem_caches.len = mem_sizes.len;
    heap += @sizeOf(MCache) * mem_caches.len;

    for (0..mem_caches.len) |i| {
        mem_caches[i] = MCache.new(@intCast(i));
    }
}

var mem_caches:[]MCache = undefined;

//const MStat = struct {
//    used:u64
//};
const MCache = struct {
    cls: u16,
    managed_pages: u16 = 0, // including free and full
    flags: u16 = 0,
    count_per_page: u16,
    free_list: ?*Page = null,
    full_list: ?*Page = null,
    bm_off: u64 = 0,
    pub fn new(cls: u16) @This() {
        const sz = mem_sizes[cls];
        var npp = page_size / sz;
        var bmoff:u64 = 0;
        if (npp > @bitSizeOf(u64)) { // > sizeof Page.any
            while ((page_size - (npp * sz)) * 8 < npp) {
                npp -= 1;
            }
            bmoff = npp * sz;
        }
        return .{.cls = cls, .count_per_page = @intCast(npp), .bm_off = bmoff};
    }
    pub fn alloc(m: *@This()) MemoryError![*]u8 {
        const fl =  m.free_list orelse blk: {
            const p = try allocPagesUnlocked(1);
            if (m.bm_off == 0) {
                p.any = @truncate((@as(u65, 1) << @truncate(m.count_per_page)) - 1);
            }
            p.owner = m;
            if (m.bm_off > 0) {
                var bm: []u8 = undefined;
                bm.ptr = @ptrFromInt(p.getVirAddr() + m.bm_off);
                bm.len = page_size - m.bm_off;
                @memset(bm, 0xff);
            }

            m.free_list = p;
            break :blk p;
        };
        const ret:[*]u8 = @ptrFromInt(allocObject(m, fl));
        return ret;
    }

    fn removeFromList(head: *?*Page, p: *Page) void {
        if (head.* == p) {
           head.* = p.next; 
        }
        if (p.prev) |prev| {
            prev.next = p.next;
        }
        if (p.next) |next| {
            next.prev = p.prev;
        }
        p.prev = null;
        p.next = null;
    }

    fn addToList(head: *?*Page, p: *Page) void {
        p.prev = null; 
        if (head.*) |h| {
            h.prev = p;
            p.next = h;
        } else {
            p.next = null;
        }
        head.* = p;
    }

    fn moveToFull(m: *@This(), p:*Page) void {
        p.flag |= 1;
        removeFromList(&m.free_list, p);
        addToList(&m.full_list, p);
    }

    fn moveToFree(m: *@This(), p:*Page) void {
        p.flag |= 0;
        removeFromList(&m.full_list, p);
        addToList(&m.free_list, p);
    }

    pub fn free(a: [*]u8) void {
        const addr :u64 = @intFromPtr(a);
        const p: *Page = virtAddrToPage(addr);
        if (p.objs == 0) {
            console.print("already freed:{any}!\n", .{a});
            return;
        }
        const m: *MCache = @ptrCast(@alignCast(p.owner));
        const idx = (addr & page_mask) / mem_sizes[m.cls];
        setBit(m, p, idx, true);
        const full = p.objs == m.count_per_page;
        p.objs -= 1;
        if (p.objs == 0) { // free from mcache
            removeFromList(&m.free_list, p);
            removeFromList(&m.full_list, p); // could be on the full list
            freePagesUnlocked(p, 1);
        } else if (full) { // was on full list
            m.moveToFree(p); 
        }

    }

};

fn allocObject(m: *MCache, p:*Page) usize {
    var bm:std.bit_set.DynamicBitSetUnmanaged = undefined;
    if (m.bm_off == 0) {
        bm = .{.bit_length = m.count_per_page, 
            .masks = @ptrCast(&p.any)};
    } else {
        bm = .{.bit_length = m.count_per_page, 
            .masks = @ptrFromInt(p.getVirAddr() + m.bm_off)};
    }
    const idx = bm.findFirstSet().?;
    bm.unset(idx);
    p.objs += 1;
    if (p.objs == m.count_per_page) { // move to full
        m.moveToFull(p);
    }
    return p.getVirAddr() + idx * mem_sizes[m.cls];
}

fn setBit(m:*MCache, p:*Page, idx:usize, value:bool) void {
    std.debug.assert(idx < m.count_per_page);
    if (m.bm_off == 0) {
        var bm:std.bit_set.DynamicBitSetUnmanaged = .{.bit_length = m.count_per_page, 
            .masks = @ptrCast(&p.any)};
        bm.setValue(idx, value);
    } else {
        var bm:std.bit_set.DynamicBitSetUnmanaged = .{.bit_length = m.count_per_page, 
            .masks = @ptrFromInt(p.getVirAddr() + m.bm_off)};
        bm.setValue(idx, value);
    }
}

fn virtAddrToPage(addr: u64) *Page {
    const pm:[*]Page = @ptrFromInt(k_page_map);
    const idx = phyAddr(addr) >> page_shift;
    return &pm[idx];
}

const mem_sizes = [_]usize{ 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 2048, 4096};
fn mCompare(m1: usize, m2: usize) std.math.Order {
    return std.math.order(m1, m2);
}

fn toMemCls(size: usize, sizes: []const usize) usize {
    return std.sort.upperBound(usize, sizes, size-1, mCompare);
}
pub fn kmalloc(n: usize, a: usize) MemoryError![*]u8 {
    const v = lock.cli(); 
    defer lock.sti(v);
    const lower = std.sort.lowerBound(usize, &mem_sizes, a, mCompare);
    const mci = lower + toMemCls(n, mem_sizes[lower..]);
    if (mci >= mem_caches.len) {
        // FIXME: huge allocation, direct page allocation?
        const np = (n + page_mask) >> page_shift;
        const p = try allocPagesUnlocked(np);
        return @ptrFromInt(p.getVirAddr());
    } else {
        const mc = &mem_caches[mci];
        return mc.alloc();
    }
}

// TODO: add resize

pub fn kfree(p: []u8) void {
    const v = lock.cli(); 
    defer lock.sti(v);
    if (p.len > mem_sizes[mem_sizes.len - 1]) {
        // huge allocation, not managed by mcache
        const np = (p.len + page_mask) >> page_shift;
        const pg = virtAddrToPage(@intFromPtr(p.ptr));
        freePagesUnlocked(pg, np);
        return;
    }

    MCache.free(p.ptr);
}

pub fn allocPages(n:usize) MemoryError!*Page {
    const v = lock.cli(); 
    defer lock.sti(v);
    return allocPagesUnlocked(n);
}

/// find n consecutive free pages
fn allocPagesUnlocked(n: usize) MemoryError!*Page {
    var it = page_bitmap.iterator(.{});
    var count:u64 = 0;
    var idx: ?usize = null;
    var prev: ?usize = null;
    while (it.next()) |i| {
        if (idx == null or (prev != null and prev.? + 1 < i)) {
            idx = i;
            prev = null;
            count = 0;
        }
        count += 1;
        if (count >= n) break;
        prev = i;
    }
    if (count < n)  return MemoryError.OutOfMemory;
    const pm:[*]Page = @ptrFromInt(k_page_map);
    // mark as allocated
    page_bitmap.setRangeValue(.{.start = idx.?, .end = idx.?+count}, false);
    used_pages += count;
    return &pm[idx.?];
}

inline fn pfn2Page(pfn: u64) *Page {
    const pm:[*]Page = @ptrFromInt(k_page_map);
    return &pm[pfn];
}

fn freePagesUnlocked(p: *Page, n: usize) void {
    const pfn = (@as(u64, @intFromPtr(p)) - k_page_map) / @sizeOf(Page);
    page_bitmap.setRangeValue(.{.start = pfn, .end = pfn + n}, true);
    used_pages -= n;
}

pub fn freePages(p: *Page, n: usize) void {
    const v = lock.cli();
    defer lock.sti(v);
    freePagesUnlocked(p, n);
}

pub const MemStat = struct {
    used_pages:u64,
    free_pages:u64
};

pub fn getMemStat() MemStat {
    return .{.used_pages = used_pages, .free_pages = max_pfn + 1 - used_pages};
}

//test "mem test" {
//    const expect = std.testing.expect;
//    try expect(toMemCls(1) == 0);
//    try expect(toMemCls(2) == 0);
//    try expect(toMemCls(3) == 0);
//    try expect(toMemCls(4) == 0);
//    try expect(toMemCls(8) == 0);
//    try expect(toMemCls(9) == 1);
//    try expect(toMemCls(15) == 1);
//    try expect(toMemCls(16) == 1);
//    try expect(toMemCls(17) == 2);
//    try expect(toMemCls(23) == 2);
//    try expect(toMemCls(24) == 2);
//    try expect(toMemCls(25) == 3);
//    try expect(toMemCls(31) == 3);
//    try expect(toMemCls(32) == 3);
//    try expect(toMemCls(33) == 4);
//    try expect(toMemCls(1023) == 31);
//    try expect(toMemCls(1024) == 31);
//    try expect(toMemCls(1025) == 32);
//    try expect(toMemCls(2047) == 32);
//    try expect(toMemCls(2048) == 32);
//    try expect(toMemCls(2049) == 33);
//    try expect(toMemCls(4096) == 33);
//    try expect(toMemCls(4097) == 34);
//    try expect(toMemCls(10000) == mem_sizes.len);
//}


