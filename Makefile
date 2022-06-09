BPF_SRC := src/dropall.c
LDR_SRC := src/loader.c

OBJDUMP = llvm-objdump
RM = rm -f

CC = clang
TARGET = -target bpf
CFLAGS = -O2

.PHONY: all
all: ebpf.o loader dump

ebpf.o: $(BPF_SRC)
	$(CC) $(TARGET) $(CFLAGS) -c $? -o $@

loader: $(LDR_SRC)
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: dump
dump: ebpf.o
	$(OBJDUMP) -D $? > ebpf_dump.s

.PHONY: clean
clean:
	$(RM) loader ebpf.o ebpf_dump.s
