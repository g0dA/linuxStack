#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "hello_kern.skel.h"

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
	struct hello_kern *skel;
	int i;

	skel = hello_kern__open_and_load();
	if (!skel) {
		fprintf(stderr, "ERROR: open and load prog failed.\n");
		goto cleanup;
	}

	i = hello_kern__attach(skel);
	if (i < 0) {
		fprintf(stderr, "ERROR: attach obj failed.\n");
		hello_kern__detach(skel);	
		goto cleanup;
	}
	read_trace_pipe();

cleanup:
	hello_kern__destroy(skel);
	return 0;
}
