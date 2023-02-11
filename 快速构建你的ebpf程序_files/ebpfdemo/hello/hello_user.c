#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <linux/bpf.h>
#include <bpf/libbpf.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

void read_trace_pipe(void)
{
    int trace_fd;

    trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0); //打开/sys/kernel/debug/tracing/trace_pipe文件
    if (trace_fd < 0)
        return;

    while (1) { //循环输出文件内容
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = 0;
            puts(buf);
        }
    }
}

int main(int argc, char *argv[]) {
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	
	obj = bpf_object__open_file("hello_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: open BPF object file failed\n");
		return 0;
	}
	
	prog = bpf_object__find_program_by_name(obj, "hello");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		return 0;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}
	read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
