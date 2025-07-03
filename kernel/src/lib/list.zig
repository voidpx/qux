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

        pub fn newNode(self: *Self) !*Node {
            return try self.alloc.create(Node);
        }

        pub fn delNode(self: *Self, node: *Node) void {
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

}
