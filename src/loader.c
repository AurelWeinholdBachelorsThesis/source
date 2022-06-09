#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>



int
main(int argc, char* argv[])
{
	if (argc < 2) {
		printf("Usage: ./loader filename\n");
		return 0;
	}

	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
	};

	char filename[32];
	snprintf(filename, sizeof(filename), "%s", argv[0]);

	prog_load_attr.file = filename;


	struct bpf_object* prog_obj;
	int prog_fd;
	if (bpf_prog_load_xattr(&prog_load_attr, &prog_obj, &prog_fd))
		return 1;

	printf("Successfully loaded XPD eBPF\n");
	return 0;
}
