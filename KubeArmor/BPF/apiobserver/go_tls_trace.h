/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * go_tls_trace.h — BPF uprobes for Go crypto/tls.(*Conn).Read/Write.
 *
 * Captures decrypted TLS plaintext from Go applications by probing
 * the crypto/tls.Conn methods. Adapted from Pixie's go_tls_trace.c.
 *
 * FD extraction chain:
 *   tls.Conn → .conn (net.Conn interface) → .(*net.TCPConn) → .fd → .pfd → .Sysfd
 *
 * Uses the same offset table and goroutine-based correlation as go_http2_trace.h.
 */

/* Requires: go_http2_trace.h (for go_addr_key, GOROUTINE_PTR, GO_PARAM*,
 *           go_addr_key_init, get_offsets, go_offset, emit_ssl_event) */

/* ---- TLS connection arguments saved between entry and return ---- */
struct go_tls_conn_args {
  u64 conn_ptr;       /* tls.Conn* (receiver) */
  u64 plaintext_ptr;  /* []byte data pointer (first element of slice) */
};

/* ---- BPF Maps ---- */

/* Goroutine key → in-flight TLS conn args (entry → return bridge). */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, struct go_addr_key);
  __type(value, struct go_tls_conn_args);
} active_go_tls_conn_op SEC(".maps");

/* ---- Helpers ---- */

/*
 * get_fd_from_tls_conn — Extract the socket FD from a tls.Conn*.
 *
 * Walks the struct chain:
 *   tls.Conn + tls_conn_conn_offset → net.Conn interface (type, ptr)
 *   → *net.TCPConn + conn_fd_offset → *netFD
 *   → netFD + fd_sysfd_offset → int (the actual FD)
 *
 * Returns the FD or INVALID_FD on failure.
 */
static __always_inline s32 get_fd_from_tls_conn(void *conn_ptr,
                                                  struct go_offset_table *ot) {
  if (!conn_ptr || !ot)
    return INVALID_FD;

  s64 tls_conn_conn_off = go_offset(ot, GO_OFF_TLS_CONN_CONN);
  s64 conn_fd_off = go_offset(ot, GO_OFF_CONN_FD);
  s64 fd_sysfd_off = go_offset(ot, GO_OFF_FD_SYSFD);

  if (tls_conn_conn_off < 0 || conn_fd_off < 0 || fd_sysfd_off < 0)
    return INVALID_FD;

  /* Step 1: Read net.Conn interface at tls.Conn + tls_conn_conn_off.
   * Go interface = {type uintptr; data unsafe.Pointer}, 16 bytes.
   * We only need the data pointer (offset +8). */
  void *conn_data = NULL;
  if (bpf_probe_read_user(&conn_data, sizeof(conn_data),
                           conn_ptr + tls_conn_conn_off + 8) != 0)
    return INVALID_FD;
  if (!conn_data)
    return INVALID_FD;

  /* Step 2: Read netFD pointer from *net.TCPConn at conn_data + conn_fd_off. */
  void *netfd_ptr = NULL;
  if (bpf_probe_read_user(&netfd_ptr, sizeof(netfd_ptr),
                           conn_data + conn_fd_off) != 0)
    return INVALID_FD;
  if (!netfd_ptr)
    return INVALID_FD;

  /* Step 3: Read Sysfd (int) from netFD at netfd_ptr + fd_sysfd_off. */
  s32 fd = INVALID_FD;
  if (bpf_probe_read_user(&fd, sizeof(fd),
                           netfd_ptr + fd_sysfd_off) != 0)
    return INVALID_FD;

  return fd;
}

/* ---- Probes ---- */

/*
 * uprobe: crypto/tls.(*Conn).Write
 *
 * Go signature:
 *   func (c *Conn) Write(b []byte) (int, error)
 *
 * Register ABI (Go 1.17+ amd64):
 *   c = rax (GO_PARAM1), b.ptr = rbx (GO_PARAM2)
 */
SEC("uprobe/tls_Conn_Write")
int ka_uprobe_tls_conn_write(struct pt_regs *ctx) {
  /* Mark this thread as "inside Go TLS" to suppress nested encrypted syscalls. */
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u8 one = 1;
  bpf_map_update_elem(&go_tls_user_space_call_map, &pid_tgid, &one, BPF_ANY);

  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  struct go_tls_conn_args args = {
    .conn_ptr = (u64)GO_PARAM1(ctx),
    .plaintext_ptr = (u64)GO_PARAM2(ctx),
  };

  bpf_map_update_elem(&active_go_tls_conn_op, &g_key, &args, BPF_ANY);
  return 0;
}

/*
 * uprobe (ret-inst): crypto/tls.(*Conn).Write
 *
 * Return value:
 *   n int is in return register at RET instruction
 */
SEC("uprobe/tls_Conn_Write_retinst")
int ka_uprobe_tls_conn_write_retinst(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  struct go_tls_conn_args *args =
    bpf_map_lookup_elem(&active_go_tls_conn_op, &g_key);
  if (!args)
    goto out;

  /* Read return value: n = number of bytes written. */
  s64 n = (s64)GO_PARAM1(ctx);
  if (n <= 0)
    goto done;

  /* Get offset table for FD extraction. */
  struct go_offset_table *ot = get_offsets();
  if (!ot)
    goto done;

  /* Walk tls.Conn → conn → TCPConn → fd.Sysfd */
  s32 fd = get_fd_from_tls_conn((void *)args->conn_ptr, ot);
  if (fd == INVALID_FD)
    goto done;

  u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
  emit_ssl_event(tgid, fd, (void *)args->plaintext_ptr, (u32)n, DIR_EGRESS);

done:
  bpf_map_delete_elem(&active_go_tls_conn_op, &g_key);
out:
  /* Clear syscall suppression flag. */
  {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&go_tls_user_space_call_map, &pid_tgid);
  }
  return 0;
}

/*
 * uprobe: crypto/tls.(*Conn).Read
 *
 * Go signature:
 *   func (c *Conn) Read(b []byte) (int, error)
 *
 * Register ABI:
 *   c = rax (GO_PARAM1), b.ptr = rbx (GO_PARAM2)
 */
SEC("uprobe/tls_Conn_Read")
int ka_uprobe_tls_conn_read(struct pt_regs *ctx) {
  /* Mark this thread as "inside Go TLS" to suppress nested encrypted syscalls. */
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u8 one = 1;
  bpf_map_update_elem(&go_tls_user_space_call_map, &pid_tgid, &one, BPF_ANY);

  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  struct go_tls_conn_args args = {
    .conn_ptr = (u64)GO_PARAM1(ctx),
    .plaintext_ptr = (u64)GO_PARAM2(ctx),
  };

  bpf_map_update_elem(&active_go_tls_conn_op, &g_key, &args, BPF_ANY);
  return 0;
}

/*
 * uprobe (ret-inst): crypto/tls.(*Conn).Read
 *
 * Return value:
 *   n int (rax), err error (rbx)
 *
 * We read the decrypted plaintext from the buffer saved at entry.
 */
SEC("uprobe/tls_Conn_Read_retinst")
int ka_uprobe_tls_conn_read_retinst(struct pt_regs *ctx) {
  void *goroutine_addr = GOROUTINE_PTR(ctx);
  struct go_addr_key g_key = {};
  go_addr_key_init(&g_key, goroutine_addr);

  struct go_tls_conn_args *args =
    bpf_map_lookup_elem(&active_go_tls_conn_op, &g_key);
  if (!args)
    goto out;

  /* Read return value: n = number of bytes read. */
  s64 n = (s64)GO_PARAM1(ctx);
  if (n <= 0)
    goto done;

  struct go_offset_table *ot = get_offsets();
  if (!ot)
    goto done;

  s32 fd = get_fd_from_tls_conn((void *)args->conn_ptr, ot);
  if (fd == INVALID_FD)
    goto done;

  u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
  emit_ssl_event(tgid, fd, (void *)args->plaintext_ptr, (u32)n, DIR_INGRESS);

done:
  bpf_map_delete_elem(&active_go_tls_conn_op, &g_key);
out:
  /* Clear syscall suppression flag. */
  {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&go_tls_user_space_call_map, &pid_tgid);
  }
  return 0;
}
