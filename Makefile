BPF_SRC := src/dropall.c

OBJDUMP = llvm-objdump
RM = rm -f

CC = clang
TARGET = -target bpf
CFLAGS = -O2

.PHONY: all
all: ebpf.o dump

ebpf.o: $(BPF_SRC)
	$(CC) $(TARGET) $(CFLAGS) -c $? -o $@ 

dump: ebpf.o
	$(OBJDUMP) -D $? > ebpf_dump.s

clean:
	$(RM) ebpf.o ebpf_dump.s
