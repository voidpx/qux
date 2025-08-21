/// handle ref-counted objects
const std = @import("std");
const mem = @import("mem.zig");
const Count = std.atomic.Value(u64);
const alloc = mem.allocator;
const Object = struct {
    const Self = @This();
    ref_count:Count = Count.init(1),
    dtor:?*const fn(*anyopaque) void,
    fn __get(this:*Self) bool {
        if (this.ref_count.fetchAdd(1, std.builtin.AtomicOrder.acquire) == 0) {
            return false;
        }
        return true;
    }
    fn __put(this:*Self) bool {
        if (this.ref_count.fetchSub(1, std.builtin.AtomicOrder.release) == 1) {
            return true;
        }
        return false;
    }
};

pub fn new(comptime T:type, ctor:?*const fn(*T) anyerror!void, dtor:?*const fn(*T) void) !*T {
    const t = getObjType(T);
    const o = try alloc.create(t);
    o.__obj_base = .{.ref_count = Count.init(1), .dtor = @ptrCast(dtor)};
    if (ctor) |c| {
        c(&o.object) catch |err| {
            alloc.destroy(o);
            return err;
        };
    }
    return &o.object; 
}

inline fn getObjType(comptime T:type) type {
    return struct {
        __obj_base:Object,
        object:T
    };
}

pub fn put(obj:anytype) void {
    const ti = @typeInfo(@TypeOf(obj));
    std.debug.assert(ti == .pointer);
    const ot = ti.pointer.child;
    const bt = getObjType(ot);
    const op = toBaseObj(obj, bt);
    if (op.__obj_base.__put()) {
        if (op.__obj_base.dtor) |d| {
            d(&op.object);
        }
        alloc.destroy(op);
    }
}

inline fn toBaseObj(obj:anytype, tp:type) *tp {
    var ptr:u64 = @intFromPtr(obj);
    const offo = @offsetOf(tp, "object");
    const offb = @offsetOf(tp, "__obj_base");
    const diff = offo - offb;
    ptr -= diff;
    const op: *tp = @ptrFromInt(ptr);
    return op;
}

pub fn getRefCount(obj:anytype) u64 {
    const ti = @typeInfo(@TypeOf(obj));
    comptime std.debug.assert(ti == .pointer);
    const ot = ti.pointer.child;
    const bt = getObjType(ot);
    const op = toBaseObj(obj, bt);
    return op.__obj_base.ref_count.raw;
}

pub fn get(obj:anytype) ?@TypeOf(obj) {
    const ti = @typeInfo(@TypeOf(obj));
    std.debug.assert(ti == .pointer);
    const ot = ti.pointer.child;
    const bt = getObjType(ot);
    const op = toBaseObj(obj, bt);
    if (op.__obj_base.__get()) {
        return obj;
    }
    return null;
}

//var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//var alloc = gpa.allocator();
//test "test ref count" {
//    const expect = std.testing.expect;
//    const T = struct {
//        a:u32,
//        b:u32,
//        const x = 5;
//        fn testf(t: *@This()) u32 {
//            return t.a;
//        }
//    };
//    const o = try new(T, null, null);
//    const obj = o;
//    try expect(get(obj) != null);
//    try expect(get(obj) != null);
//    put(obj);
//    put(obj);
//    put(obj);
//}

