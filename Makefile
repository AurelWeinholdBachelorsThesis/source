OBJ := src/dropall.c

OBJDUMP = llvm-objdump

CC = clang
TARGET = -target bpf
CFLAGS = -O2

.PHONY: all
all: ebpf.o dump

ebpf.o: $(OBJ)
	$(CC) $(TARGET) $(CFLAGS) -c $? -o $@ 

dump: ebpf.o
	$(OBJDUMP) -D $? > ebpf_dump.s
