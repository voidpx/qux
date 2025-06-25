
FLAGS=-g

OBJ = boot.o head.o
LDS = setup.ld.S

setup: $(OBJ)
	gcc -E -o $(LDS).tmp $(LDS)  
	ld -T $(LDS).tmp -o $@ $^	

boot.o: boot.S
	gcc -E -DKERNEL_FILE=\"../kernel/zig-out/bin/qux\" $< | as -g --32 -march=i686 -o $@ 

head.o: head.c
	gcc -g -Wno-pointer-to-int-cast -fno-pie -ffreestanding -c -m32 -o $@ $^
	

.PHONY: clean

clean:
	rm -f boot.o setup.o *.tmp


