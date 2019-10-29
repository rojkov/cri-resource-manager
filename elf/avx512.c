
#include <uapi/linux/bpf.h>

#include <asm/page_types.h>

/* asm/fpu/types.h assumes __packed is defined */
#define __packed __attribute__((packed))
#include <asm/fpu/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

static int (*bpf_probe_read)(void *dst, u64 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read;

static u64 (*bpf_get_current_cgroup_id)(void) = (void *)
	BPF_FUNC_get_current_cgroup_id;

static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  u64 flags) = (void *)BPF_FUNC_map_update_elem;

static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)
	BPF_FUNC_map_lookup_elem;

#define bpf_printk(fmt, ...)                                                   \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})
static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
			       ...) = (void *)BPF_FUNC_trace_printk;

struct bpf_map_def
	SEC("maps/all_context_switch_count") all_context_switch_count_hash = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u64),
		.value_size = sizeof(u32),
		.max_entries = 1024,
	};

struct bpf_map_def
	SEC("maps/avx_context_switch_count") avx_context_switch_count_hash = {
		.type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(u64),
		.value_size = sizeof(u32),
		.max_entries = 1024,
	};

struct bpf_map_def SEC("maps/cpu") cpu_hash = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(u32),
	.max_entries = 128,
};

struct sched_switch_args {
	u64 pad;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long long prev_state;
	char next_comm[16];
	int next_pid;
	int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int tracepoint__sched_switch(struct sched_switch_args *args)
{
	u64 cgroup_id = bpf_get_current_cgroup_id();
	u32 *count;
	u32 new_count = 1;

	count = bpf_map_lookup_elem(&all_context_switch_count_hash, &cgroup_id);
	if (count) {
		new_count = *count + 1;
	}

	bpf_map_update_elem(&all_context_switch_count_hash, &cgroup_id,
			    &new_count, BPF_ANY);

	return 0;
}

struct x86_fpu_args {
	u64 pad;
	struct fpu *fpu;
	bool load_fpu;
	u64 xfeatures;
	u64 xcomp_bv;
};

SEC("tracepoint/x86_fpu/x86_fpu_regs_deactivated")
int tracepoint__x86_fpu_regs_deactivated(struct x86_fpu_args *args)
{
	u32 *counter;
	u32 ts;
	bpf_probe_read(&ts, sizeof(u32), (void *)&args->fpu->avx512_timestamp);

	if (ts == 0) {
		return 0;
	}

	unsigned int last_cpu;
	bpf_probe_read(&last_cpu, sizeof(last_cpu),
		       (void *)&args->fpu->last_cpu);

	u32 count = 1;
	counter = bpf_map_lookup_elem(&cpu_hash, &last_cpu);
	if (counter) {
		count = *counter + 1;
	}
	bpf_map_update_elem(&cpu_hash, &last_cpu, &count, BPF_ANY);

	u64 cgroup_id = bpf_get_current_cgroup_id();

	count = 1;
	counter = bpf_map_lookup_elem(&avx_context_switch_count_hash, &cgroup_id);
	if (counter) {
		count = *counter + 1;
	}
	bpf_map_update_elem(&avx_context_switch_count_hash, &cgroup_id,
			    &count, BPF_ANY);

	bpf_printk("AVX512 detected in cgroup %llu\n", cgroup_id);
	return 0;
}

char _license[] SEC("license") = "GPL";

// this number will be interpreted by gobpf-elf-loader to set the current
// running kernel version
unsigned int _version SEC("version") = 0xFFFFFFFE;
