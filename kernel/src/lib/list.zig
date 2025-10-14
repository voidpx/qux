/// A linked list that manages the Nodes itself.
const std = @import("std");
pub fn List(comptime T:type) type {
    return struct {
        const Self = @This();
        const DList = std.DoublyLinkedList(T);
        const Node = DList.Node;
        list: DList,
        alloc: std.mem.Allocator,

        pub fn new(a: std.mem.Allocator) Self {
            return Self{.list = .{}, .alloc = a};
        }

        pub fn drop(this:*@This()) void {
            while (this.popFirst()) |_| {
            }
        }

        fn newNode(self: *Self) !*Node {
            return try self.alloc.create(Node);
        }

        fn delNode(self: *Self, node: *Node) void {
            self.alloc.destroy(node);
        }

        pub fn append(self: *Self, data: T) !*Node {
            var node = try self.alloc.create(Node);
            node.data = data;
            self.list.append(node);
            return node;
        }

        pub fn insertAfter(self: *Self, node: *Node, new_node: *Node) void {
            self.list.insertAfter(node, new_node);
        }

        pub fn insertBefore(self: *Self, node: *Node, new_node: *Node) void {
            self.list.insertBefore(node, new_node);
        }


        pub fn concatByMoving(list1: *Self, list2: *Self) void {
            list1.list.concatByMoving(&list2.list);
        }
    
        pub fn pop(self: *Self) ?T {
            const n = (&self.list).pop() orelse return null;
            const r = n.data;
            self.delNode(n);
            return r;
        }

        pub fn popFirst(self: *Self) ?T {
            const n = (&self.list).popFirst() orelse return null;
            const r = n.data;
            self.delNode(n);
            return r;
        }
        
        pub fn prepend(self: *Self, data: T) !*Node {
            var node = try self.alloc.create(Node);
            node.data = data;
            self.list.prepend(node);
            return node;
        }
        pub fn remove(self: *Self, node: *Node) void {
            self.list.remove(node);
            self.delNode(node);
        }
        pub fn len(self: *Self) usize {
            return self.list.len;
        }
    };
}

pub fn LinkedList(comptime T: type) type {
    // TODO: lock
    return struct {
        const Self = @This();
        pub const Node = struct {
            list: ?*Self = null,
            prev: ?*Node = null,
            next: ?*Node = null,
            data: T,
            fn remove(n:*Node) void {
                if (n.list == null) return; // not on list
                n.list.?.remove(n.list.?, n); 
            }
        };

        first: ?*Node = null,
        last: ?*Node = null,
        len: usize = 0,

        pub fn append(self:*Self, n:*Node) void {
            n.next = null;
            n.prev = self.last;
            n.list = self;
            if (self.last) |last| {
                last.next = n;
            } else {
                std.debug.assert(self.first == null);
                self.first = n;
            }
            self.last = n;
            n.list = self;
            self.len += 1;
        }

        pub fn prepend(self:*Self, n:*Node) void {
            n.prev = null;
            n.next = self.first;
            n.list = self;
            if (self.first) |first| {
                first.prev = n;
            } else {
                std.debug.assert(self.last == null);
                self.last = n;
            }
            self.first = n;
            n.list = self;
            self.len += 1;
        }

        pub fn popFirst(self:*Self) ?*Node {
            if (self.first) |f| {
                self.remove(f);
                return f;
            }
            return null;
        }

        pub fn pop(self:*Self) ?*Node {
            if (self.last) |l| {
                self.remove(l);
                return l;
            }
            return null;
        }

        pub fn remove(self:*Self, n:*Node) void {
            if (n.list != self) {
                // node doesn't belong to the list
                //std.debug.panic("node not belonging to list\n", .{});
                return;
            }
            if (self.len == 0) {
                //std.debug.panic("remove from empty list\n", .{});
                return;
            }
            if (n.prev) |p| {
                p.next = n.next;
            } else {
                // n is the first
                self.first = n.next;
            }
            if (n.next) |a| {
                a.prev = n.prev;
            } else {
                // n is the last
                self.last = n.prev;
            }
            n.list = null;
            n.prev = null;
            n.next = null;
            self.len -= 1;
        }

        pub fn count(self:*Self) usize {
            return self.len;
        }
    };
}

test "test linked list" {
    var a = std.heap.GeneralPurposeAllocator(.{}){};
    var list = List(u64).new((&a).allocator()); 
    _=try list.append(3);
    _=try list.append(4);
    _=try list.append(5);
    _=try list.append(6);
    _=try list.append(7);
    try std.testing.expect(list.len() == 5);
    _=list.pop();
    _=list.pop();
    _=list.pop();
    _=list.pop();
    _=list.pop();
    try std.testing.expect(list.len() == 0);

    const DList = LinkedList(u64);
    var n1 = DList.Node{.data = 1};
    var n2 = DList.Node{.data = 2};
    var n3 = DList.Node{.data = 3};
    var n4 = DList.Node{.data = 4};

    var l = DList{};
    l.append(&n1);
    l.append(&n2);
    l.prepend(&n3);
    l.prepend(&n4);

    try std.testing.expect(l.count() == 4);
    try std.testing.expect(l.pop().?.data == 2);
    try std.testing.expect(l.popFirst().?.data == 4);
    try std.testing.expect(l.count() == 2);
    try std.testing.expect(n1.list.? == &l);
    try std.testing.expect(n1.list.? == &l);
    try std.testing.expect(n1.list.? == &l);
    try std.testing.expect(n1.list.? == &l);

    l.remove(&n3);
    try std.testing.expect(l.first.?.data == 1);    
    try std.testing.expect(n1.prev == null and n1.next == null);
    try std.testing.expect(n2.prev == null and n2.next == null);
    try std.testing.expect(n3.prev == null and n3.next == null);
    try std.testing.expect(n4.prev == null and n4.next == null);

    try std.testing.expect(n1.list != null);
    try std.testing.expect(n2.list == null);
    try std.testing.expect(n3.list == null);
    try std.testing.expect(n4.list == null);
}
