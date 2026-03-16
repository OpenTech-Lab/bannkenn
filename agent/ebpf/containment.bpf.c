#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

#define BK_PATH_CAPACITY 256
#define BK_PROCESS_CAPACITY 128
#define BK_MAX_WATCH_ROOTS 16
#define BK_MAX_PROTECTED_ROOTS 16
#define BK_MAX_PENDING_OPENS 1024
#define BK_MAX_TRACKED_FILES 8192

#define BK_EVENT_KIND_EXEC 1u
#define BK_EVENT_KIND_EXIT 2u

#define BK_O_WRONLY 01
#define BK_O_RDWR 02
#define BK_O_CREAT 0100
#define BK_O_TRUNC 01000

struct raw_behavior_ring_event {
    __u32 pid;
    __u32 event_kind;
    __u64 bytes_written;
    __u32 created;
    __u32 modified;
    __u32 renamed;
    __u32 deleted;
    __u32 protected_path_touched;
    __u32 path_len;
    __u32 process_name_len;
    char path[BK_PATH_CAPACITY];
    char process_name[BK_PROCESS_CAPACITY];
};

struct root_path_entry {
    __u32 len;
    char path[BK_PATH_CAPACITY];
};

struct pending_open {
    __u32 flags;
    __u32 protected_path_touched;
    __u32 path_len;
    char path[BK_PATH_CAPACITY];
};

struct tracked_fd_key {
    __u32 pid;
    __u32 fd;
};

struct tracked_fd_state {
    __u32 protected_path_touched;
    __u32 path_len;
    char path[BK_PATH_CAPACITY];
};

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

struct trace_event_raw_sys_exit {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __s64 ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} BK_EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BK_MAX_WATCH_ROOTS);
    __type(key, __u32);
    __type(value, struct root_path_entry);
} BK_WATCH_ROOTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BK_MAX_PROTECTED_ROOTS);
    __type(key, __u32);
    __type(value, struct root_path_entry);
} BK_PROTECTED_ROOTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BK_MAX_PENDING_OPENS);
    __type(key, __u64);
    __type(value, struct pending_open);
} BK_PENDING_OPEN SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BK_MAX_TRACKED_FILES);
    __type(key, struct tracked_fd_key);
    __type(value, struct tracked_fd_state);
} BK_TRACKED_FILES SEC(".maps");

static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) =
    (void *)BPF_FUNC_get_current_comm;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_FUNC_probe_read_user_str;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
    (void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)BPF_FUNC_ringbuf_submit;

static __always_inline __u32 current_tgid(void)
{
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 cstr_len(const char *value, __u32 capacity)
{
    __u32 len = 0;

    for (int i = 0; i < BK_PROCESS_CAPACITY; i++) {
        if ((__u32)i >= capacity || value[i] == '\0') {
            break;
        }
        len++;
    }

    return len;
}

static __always_inline void copy_path(char *dst, const char *src, __u32 len)
{
    for (int i = 0; i < BK_PATH_CAPACITY; i++) {
        if ((__u32)i < len) {
            dst[i] = src[i];
        } else {
            dst[i] = '\0';
        }
    }
}

static __always_inline int prefix_matches(const char *path, const struct root_path_entry *prefix)
{
    if (!prefix || prefix->len == 0 || prefix->len >= BK_PATH_CAPACITY) {
        return 0;
    }

    for (int i = 0; i < BK_PATH_CAPACITY; i++) {
        if ((__u32)(i + 1) == prefix->len) {
            if (path[i] != prefix->path[i]) {
                return 0;
            }
            if (prefix->path[i] == '/') {
                return 1;
            }
            return path[i + 1] == '\0' || path[i + 1] == '/';
        }

        if (path[i] != prefix->path[i] || path[i] == '\0') {
            return 0;
        }
    }

    return 0;
}

static __always_inline int is_path_in_map(const char *path, void *map, __u32 max_entries)
{
    for (int i = 0; i < BK_MAX_WATCH_ROOTS; i++) {
        __u32 index = i;
        struct root_path_entry *entry;

        if ((__u32)i >= max_entries) {
            break;
        }

        entry = bpf_map_lookup_elem(map, &index);
        if (prefix_matches(path, entry)) {
            return 1;
        }
    }

    return 0;
}

static __always_inline int watched_path(const char *path)
{
    return is_path_in_map(path, &BK_WATCH_ROOTS, BK_MAX_WATCH_ROOTS);
}

static __always_inline int protected_path(const char *path)
{
    return is_path_in_map(path, &BK_PROTECTED_ROOTS, BK_MAX_PROTECTED_ROOTS);
}

static __always_inline int read_watched_user_path(const char *user_path,
                                                  char *path,
                                                  __u32 *path_len,
                                                  __u32 *protected_hit)
{
    long copied;

    if (!user_path) {
        return 0;
    }

    copied = bpf_probe_read_user_str(path, BK_PATH_CAPACITY, user_path);
    if (copied <= 1) {
        return 0;
    }

    *path_len = (__u32)(copied - 1);
    if (!watched_path(path)) {
        return 0;
    }

    *protected_hit = protected_path(path);
    return 1;
}

struct file_emit_spec {
    __u32 pid;
    __u32 path_len;
    __u32 protected_hit;
    __u32 created;
    __u32 modified;
    __u32 renamed;
    __u32 deleted;
    __u64 bytes_written;
    const char *path;
};

static __always_inline struct raw_behavior_ring_event *reserve_event(void)
{
    return bpf_ringbuf_reserve(&BK_EVENTS, sizeof(struct raw_behavior_ring_event), 0);
}

static __always_inline void populate_common_fields(struct raw_behavior_ring_event *event,
                                                   __u32 pid,
                                                   __u32 event_kind)
{
    if (!event) {
        return;
    }

    event->pid = pid;
    event->event_kind = event_kind;
    bpf_get_current_comm(event->process_name, sizeof(event->process_name));
    event->process_name_len = cstr_len(event->process_name, BK_PROCESS_CAPACITY);
}

static __always_inline void emit_lifecycle_event(__u32 pid, __u32 event_kind)
{
    struct raw_behavior_ring_event *event = reserve_event();

    populate_common_fields(event, pid, event_kind);
    if (event) {
        bpf_ringbuf_submit(event, 0);
    }
}

static __always_inline void emit_file_event(const struct file_emit_spec *spec)
{
    struct raw_behavior_ring_event *event = reserve_event();
    __u32 capped_path_len = spec->path_len;

    if (!event || !spec) {
        return;
    }

    if (capped_path_len >= BK_PATH_CAPACITY) {
        capped_path_len = BK_PATH_CAPACITY - 1;
    }

    populate_common_fields(event, spec->pid, 0);
    event->bytes_written = spec->bytes_written;
    event->created = spec->created;
    event->modified = spec->modified;
    event->renamed = spec->renamed;
    event->deleted = spec->deleted;
    event->protected_path_touched = spec->protected_hit;
    event->path_len = capped_path_len;

    if (spec->path && capped_path_len > 0) {
        copy_path(event->path, spec->path, capped_path_len);
    }

    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/sched/sched_process_exec")
int bk_sched_exec(void *ctx)
{
    (void)ctx;
    emit_lifecycle_event(current_tgid(), BK_EVENT_KIND_EXEC);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int bk_sched_exit(void *ctx)
{
    (void)ctx;
    emit_lifecycle_event(current_tgid(), BK_EVENT_KIND_EXIT);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int bk_file_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    const char *user_path = (const char *)ctx->args[1];
    struct pending_open pending = {};

    if (!read_watched_user_path(user_path,
                                pending.path,
                                &pending.path_len,
                                &pending.protected_path_touched)) {
        return 0;
    }

    pending.flags = (__u32)ctx->args[2];
    bpf_map_update_elem(&BK_PENDING_OPEN, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int bk_file_openat_ret(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_open *pending = bpf_map_lookup_elem(&BK_PENDING_OPEN, &pid_tgid);

    if (!pending) {
        return 0;
    }

    if (ctx->ret >= 0) {
        struct tracked_fd_key key = {
            .pid = current_tgid(),
            .fd = (__u32)ctx->ret,
        };
        struct tracked_fd_state state = {
            .protected_path_touched = pending->protected_path_touched,
            .path_len = pending->path_len,
        };
        __u32 created = (pending->flags & BK_O_CREAT) ? 1u : 0u;
        __u32 modified = (pending->flags & BK_O_TRUNC) ? 1u : 0u;
        struct file_emit_spec spec = {
            .pid = key.pid,
            .path_len = pending->path_len,
            .protected_hit = pending->protected_path_touched,
            .created = created,
            .modified = modified,
            .renamed = 0,
            .deleted = 0,
            .bytes_written = 0,
            .path = pending->path,
        };

        copy_path(state.path, pending->path, pending->path_len);
        bpf_map_update_elem(&BK_TRACKED_FILES, &key, &state, BPF_ANY);

        if (created || modified) {
            emit_file_event(&spec);
        }
    }

    bpf_map_delete_elem(&BK_PENDING_OPEN, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int bk_file_write(struct trace_event_raw_sys_enter *ctx)
{
    struct tracked_fd_key key = {
        .pid = current_tgid(),
        .fd = (__u32)ctx->args[0],
    };
    struct tracked_fd_state *state = bpf_map_lookup_elem(&BK_TRACKED_FILES, &key);
    __u64 bytes_written = ctx->args[2];
    struct file_emit_spec spec;

    if (!state || bytes_written == 0) {
        return 0;
    }

    spec.pid = key.pid;
    spec.path_len = state->path_len;
    spec.protected_hit = state->protected_path_touched;
    spec.created = 0;
    spec.modified = 1;
    spec.renamed = 0;
    spec.deleted = 0;
    spec.bytes_written = bytes_written;
    spec.path = state->path;
    emit_file_event(&spec);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int bk_file_close(struct trace_event_raw_sys_enter *ctx)
{
    struct tracked_fd_key key = {
        .pid = current_tgid(),
        .fd = (__u32)ctx->args[0],
    };

    bpf_map_delete_elem(&BK_TRACKED_FILES, &key);
    return 0;
}

static __always_inline int emit_rename(const char *old_path_ptr, const char *new_path_ptr)
{
    char path[BK_PATH_CAPACITY] = {};
    __u32 path_len = 0;
    __u32 protected_hit = 0;
    struct file_emit_spec spec = {
        .pid = current_tgid(),
        .created = 0,
        .modified = 0,
        .renamed = 1,
        .deleted = 0,
        .bytes_written = 0,
        .path = path,
    };

    if (read_watched_user_path(new_path_ptr, path, &path_len, &protected_hit)) {
        spec.path_len = path_len;
        spec.protected_hit = protected_hit;
        emit_file_event(&spec);
        return 0;
    }

    if (read_watched_user_path(old_path_ptr, path, &path_len, &protected_hit)) {
        spec.path_len = path_len;
        spec.protected_hit = protected_hit;
        emit_file_event(&spec);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int bk_file_renameat(struct trace_event_raw_sys_enter *ctx)
{
    return emit_rename((const char *)ctx->args[1], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int bk_file_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    return emit_rename((const char *)ctx->args[1], (const char *)ctx->args[3]);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int bk_file_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    char path[BK_PATH_CAPACITY] = {};
    __u32 path_len = 0;
    __u32 protected_hit = 0;
    struct file_emit_spec spec = {
        .pid = current_tgid(),
        .created = 0,
        .modified = 0,
        .renamed = 0,
        .deleted = 1,
        .bytes_written = 0,
        .path = path,
    };

    if (!read_watched_user_path((const char *)ctx->args[1], path, &path_len, &protected_hit)) {
        return 0;
    }

    spec.path_len = path_len;
    spec.protected_hit = protected_hit;
    emit_file_event(&spec);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
