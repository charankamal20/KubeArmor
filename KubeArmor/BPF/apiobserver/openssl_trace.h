/* openssl_trace.h — SSL_write / SSL_read / SSL_read_ex / SSL_write_ex / SSL_shutdown uprobes.
 *
 * Adapted from Pixie's openssl_trace.c and KubeArmor's original WIP code.
 *
 * Two FD extraction methods:
 *   1. Userspace offsets: ssl->rbio->num using version-specific offsets
 *      from ssl_symaddrs map (for BoringSSL/Netty tcnative).
 *   2. Nested syscall: Track the FD from the underlying read()/write()
 *      syscall that occurs while SSL_read/SSL_write is on the stack
 *      (for OpenSSL/Python — primary method).
 *
 * Dedup: conn->is_ssl = 1 causes sock_trace.h kprobes to skip,
 * preventing duplicate (encrypted + plaintext) events.
 */
#pragma once
#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"

/* ───────────────────────────────────────────────────────────────── *
 *  FD extraction: userspace struct offset method                   *
 *  Used for BoringSSL / libnetty_tcnative (where nested syscall    *
 *  method doesn't work because BIO doesn't use real I/O)           *
 * ───────────────────────────────────────────────────────────────── */
static __always_inline s32 get_fd_from_ssl_struct(void *ssl_ptr,
                                                  u32 tgid) {
  struct ssl_symaddrs *addrs = bpf_map_lookup_elem(&ssl_symaddrs, &tgid);
  if (!addrs || addrs->ssl_rbio_offset < 0 || addrs->bio_num_offset < 0) {
    return INVALID_FD;
  }

  void *rbio = NULL;
  bpf_probe_read_user(&rbio, sizeof(rbio),
                      (void *)((u64)ssl_ptr + addrs->ssl_rbio_offset));
  if (!rbio) {
    return INVALID_FD;
  }

  int fd = 0;
  bpf_probe_read_user(&fd, sizeof(fd),
                      (void *)((u64)rbio + addrs->bio_num_offset));
  return (s32)fd;
}

/* ───────────────────────────────────────────────────────────────── *
 *  FD extraction: nested syscall method                            *
 *  Retrieves the FD captured by syscall kprobes during this SSL    *
 *  call's execution. Cleans up the map entry.                      *
 * ───────────────────────────────────────────────────────────────── */
static __always_inline s32 get_fd_from_nested_syscall(u64 pid_tgid) {
  struct nested_syscall_fd_t *nsc =
      bpf_map_lookup_elem(&ssl_user_space_call_map, &pid_tgid);
  if (!nsc) {
    return INVALID_FD;
  }

  s32 fd = nsc->fd;
  /* Warn + best-effort: if mismatched FDs, still use what we have */
  bpf_map_delete_elem(&ssl_user_space_call_map, &pid_tgid);

  return fd;
}

/* ───────────────────────────────────────────────────────────────── *
 *  Shared helpers: mark connection as SSL, emit data event         *
 * ───────────────────────────────────────────────────────────────── */
static __always_inline void mark_conn_as_ssl(u32 tgid, u32 fd) {
  struct conn_id cid = {.tgid = tgid, .fd = fd};
  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (!sp || *sp == 0)
    return;
  u64 sock_ptr = *sp;
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (conn && !conn->is_ssl) {
    conn->is_ssl = 1;
    bpf_map_update_elem(&connections, &sock_ptr, conn, BPF_EXIST);
  }
}

/* emit_ssl_event — shared emit core for all SSL probes.
 * Reads decrypted payload from buf, marks connection as SSL,
 * and submits through the ring buffer via emit_data_event(). */
static __always_inline int
emit_ssl_event(u32 tgid, s32 fd, void *buf, u32 len, u8 direction) {
  if (fd <= 0 || !buf || len == 0)
    return 0;

  bpf_printk("SSL: tgid=%u fd=%d len=%u dir=%u", tgid, fd, len, direction);

  /* Use resolve_fd_to_sock_ptr() instead of raw map lookup.
   * This provides:
   *   1. CO-RE fdtable walk as fallback (task→files→fdt→fd[n]→sk)
   *   2. Lazy population of pid_fd_to_sock + connections maps
   * Without this, SSL events for pre-existing connections or connections
   * not yet seen by connect/accept kretprobes are silently dropped. */
  u64 sock_ptr = resolve_fd_to_sock_ptr((u32)fd);
  if (sock_ptr == 0) {
    bpf_printk("SSL: resolve_fd_to_sock_ptr FAILED for fd=%d", fd);
    return 0;
  }

  /* Mark connection as SSL — suppresses kprobe path for this sock */
  mark_conn_as_ssl(tgid, (u32)fd);

  u32 zero = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
  if (!e)
    return 0;

  e->flags = FLAG_IS_SSL;
  u32 to_copy = len < MAX_DATA_SIZE ? len : MAX_DATA_SIZE;
  if (bpf_probe_read_user(e->payload, to_copy & (MAX_DATA_SIZE - 1), buf) < 0)
    return 0;
  e->data_len = to_copy;
  if (len > MAX_DATA_SIZE)
    e->flags |= FLAG_TRUNCATED;

  bpf_printk("SSL: emitting %u bytes via emit_data_event sock=0x%llx", to_copy, sock_ptr);
  return emit_data_event(sock_ptr, direction);
}

/* ═══════════════════════════════════════════════════════════════════ *
 *  USERSPACE OFFSET PATH — for BoringSSL/Netty tcnative             *
 *  FD extracted from ssl->rbio->num using struct offsets             *
 * ═══════════════════════════════════════════════════════════════════ */

/* SSL_write(SSL *ssl, const void *buf, int num) — entry */
static __always_inline int
handle_ssl_write_entry(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  void *buf = (void *)PT_REGS_PARM2(ctx);
  if (!ssl || !buf)
    return 0;

  s32 fd = get_fd_from_ssl_struct(ssl, tgid);
  if (fd == INVALID_FD)
    return 0;

  struct ssl_write_args args = {
      .ssl_ptr = (u64)ssl,
      .buf = (u64)buf,
      .ssl_ex_len = 0,
  };
  bpf_map_update_elem(&active_ssl_write_args, &pid_tgid, &args, BPF_ANY);

  /* Mark connection as SSL immediately */
  mark_conn_as_ssl(tgid, (u32)fd);

  return 0;
}

/* SSL_write return — emit data using saved args */
static __always_inline int
handle_ssl_write_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  struct ssl_write_args *args =
      bpf_map_lookup_elem(&active_ssl_write_args, &pid_tgid);
  if (!args) {
    return 0;
  }

  void *ssl = (void *)args->ssl_ptr;
  void *buf = (void *)args->buf;
  bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);

  int ret = (int)PT_REGS_RC(ctx);
  if (ret <= 0 || !buf)
    return 0;

  s32 fd = get_fd_from_ssl_struct(ssl, tgid);
  if (fd == INVALID_FD)
    return 0;

  return emit_ssl_event(tgid, fd, buf, (u32)ret, DIR_EGRESS);
}

/* SSL_read entry — save (ssl*, buf*) for uretprobe */
static __always_inline int
handle_ssl_read_entry(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  void *buf = (void *)PT_REGS_PARM2(ctx);
  if (!ssl || !buf) {
    return 0;
  }
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  s32 fd = get_fd_from_ssl_struct(ssl, tgid);
  if (fd != INVALID_FD)
    mark_conn_as_ssl(tgid, (u32)fd);

  struct ssl_read_args args = {
      .ssl_ptr = (u64)ssl,
      .buf = (u64)buf,
      .ssl_ex_len = 0,
  };
  bpf_map_update_elem(&active_ssl_read_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

/* SSL_read return — kernel has filled buf with decrypted data */
static __always_inline int
handle_ssl_read_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  struct ssl_read_args *args =
      bpf_map_lookup_elem(&active_ssl_read_args, &pid_tgid);
  if (!args) {
    return 0;
  }
  void *ssl = (void *)args->ssl_ptr;
  void *buf = (void *)args->buf;
  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);

  int ret = (int)PT_REGS_RC(ctx);
  if (ret <= 0 || !buf) {
    return 0;
  }

  s32 fd = get_fd_from_ssl_struct(ssl, tgid);
  if (fd == INVALID_FD)
    return 0;

  return emit_ssl_event(tgid, fd, buf, (u32)ret, DIR_INGRESS);
}

/* ═══════════════════════════════════════════════════════════════════ *
 *  NESTED SYSCALL FD PATH — for OpenSSL / Python / libpython        *
 *  FD captured from the underlying read()/write() syscall           *
 * ═══════════════════════════════════════════════════════════════════ */

/* Shared entry for SSL_write + SSL_write_ex (nested syscall path) */
static __always_inline int
ssl_write_entry_syscall_fd(struct pt_regs *ctx, bool is_ex_call) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  /* Signal to syscall kprobes that an SSL call is on the stack */
  struct nested_syscall_fd_t nsc = {.fd = INVALID_FD, .mismatched_fds = 0};
  bpf_map_update_elem(&ssl_user_space_call_map, &pid_tgid, &nsc, BPF_ANY);

  void *buf = (void *)PT_REGS_PARM2(ctx);

  struct ssl_write_args args = {
      .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
      .buf = (u64)buf,
      .ssl_ex_len = 0,
  };
  if (is_ex_call) {
    args.ssl_ex_len = (u64)PT_REGS_PARM4(ctx);
  }
  bpf_map_update_elem(&active_ssl_write_args, &pid_tgid, &args, BPF_ANY);

  return 0;
}

/* Shared return for SSL_write + SSL_write_ex (nested syscall path) */
static __always_inline int
ssl_write_return_syscall_fd(struct pt_regs *ctx, bool is_ex_call) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  s32 fd = get_fd_from_nested_syscall(pid_tgid);
  if (fd == INVALID_FD) {
    bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);
    return 0;
  }

  struct ssl_write_args *args =
      bpf_map_lookup_elem(&active_ssl_write_args, &pid_tgid);
  if (!args) {
    return 0;
  }

  void *buf = (void *)args->buf;
  u32 len = 0;

  if (is_ex_call && args->ssl_ex_len != 0) {
    /* SSL_write_ex: byte count written to *ssl_ex_len on success */
    u64 written = 0;
    bpf_probe_read_user(&written, sizeof(written), (void *)args->ssl_ex_len);
    len = (u32)written;
  } else {
    /* SSL_write: return value is the byte count on success */
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
      bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);
      return 0;
    }
    len = (u32)ret;
  }

  bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);

  mark_conn_as_ssl(tgid, (u32)fd);
  return emit_ssl_event(tgid, fd, buf, len, DIR_EGRESS);
}

/* Shared entry for SSL_read + SSL_read_ex (nested syscall path) */
static __always_inline int
ssl_read_entry_syscall_fd(struct pt_regs *ctx, bool is_ex_call) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  /* Signal to syscall kprobes that an SSL call is on the stack */
  struct nested_syscall_fd_t nsc = {.fd = INVALID_FD, .mismatched_fds = 0};
  bpf_map_update_elem(&ssl_user_space_call_map, &pid_tgid, &nsc, BPF_ANY);

  void *buf = (void *)PT_REGS_PARM2(ctx);

  struct ssl_read_args args = {
      .ssl_ptr = (u64)PT_REGS_PARM1(ctx),
      .buf = (u64)buf,
      .ssl_ex_len = 0,
  };
  if (is_ex_call) {
    args.ssl_ex_len = (u64)PT_REGS_PARM4(ctx);
  }
  bpf_map_update_elem(&active_ssl_read_args, &pid_tgid, &args, BPF_ANY);

  return 0;
}

/* Shared return for SSL_read + SSL_read_ex (nested syscall path) */
static __always_inline int
ssl_read_return_syscall_fd(struct pt_regs *ctx, bool is_ex_call) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = (u32)(pid_tgid >> 32);

  s32 fd = get_fd_from_nested_syscall(pid_tgid);
  if (fd == INVALID_FD) {
    bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);
    return 0;
  }

  struct ssl_read_args *args =
      bpf_map_lookup_elem(&active_ssl_read_args, &pid_tgid);
  if (!args) {
    return 0;
  }

  void *buf = (void *)args->buf;
  u32 len = 0;

  if (is_ex_call && args->ssl_ex_len != 0) {
    /* SSL_read_ex: byte count written to *readbytes on success */
    u64 readbytes = 0;
    bpf_probe_read_user(&readbytes, sizeof(readbytes),
                        (void *)args->ssl_ex_len);
    len = (u32)readbytes;
  } else {
    /* SSL_read: return value is the byte count on success */
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) {
      bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);
      return 0;
    }
    len = (u32)ret;
  }

  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);

  mark_conn_as_ssl(tgid, (u32)fd);
  return emit_ssl_event(tgid, fd, buf, len, DIR_INGRESS);
}

/* SEC handler wrappers for nested syscall FD path */
static __always_inline int
handle_ssl_write_entry_syscall_fd(struct pt_regs *ctx) {
  return ssl_write_entry_syscall_fd(ctx, false);
}
static __always_inline int
handle_ssl_write_return_syscall_fd(struct pt_regs *ctx) {
  return ssl_write_return_syscall_fd(ctx, false);
}
static __always_inline int
handle_ssl_write_ex_entry_syscall_fd(struct pt_regs *ctx) {
  return ssl_write_entry_syscall_fd(ctx, true);
}
static __always_inline int
handle_ssl_write_ex_return_syscall_fd(struct pt_regs *ctx) {
  return ssl_write_return_syscall_fd(ctx, true);
}
static __always_inline int
handle_ssl_read_entry_syscall_fd(struct pt_regs *ctx) {
  return ssl_read_entry_syscall_fd(ctx, false);
}
static __always_inline int
handle_ssl_read_return_syscall_fd(struct pt_regs *ctx) {
  return ssl_read_return_syscall_fd(ctx, false);
}
static __always_inline int
handle_ssl_read_ex_entry_syscall_fd(struct pt_regs *ctx) {
  return ssl_read_entry_syscall_fd(ctx, true);
}
static __always_inline int
handle_ssl_read_ex_return_syscall_fd(struct pt_regs *ctx) {
  return ssl_read_return_syscall_fd(ctx, true);
}

/* ═══════════════════════════════════════════════════════════════════ *
 *  SSL_shutdown — cleanup stash maps for this connection             *
 * ═══════════════════════════════════════════════════════════════════ */
static __always_inline int
handle_ssl_shutdown(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  /* Clean up any in-flight stash entries for this thread */
  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);
  bpf_map_delete_elem(&active_ssl_write_args, &pid_tgid);
  bpf_map_delete_elem(&ssl_user_space_call_map, &pid_tgid);
  return 0;
}
