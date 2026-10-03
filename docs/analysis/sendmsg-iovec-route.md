# Route: `sendmsg_iovec` (device adaptation)

> Status: **geometry verified from the image; exploit-level behaviour NOT yet
> verified on a device.** The middleware is selectable, but this row has not
> passed the real-hardware gate described in
> `docs/development/adding-a-component.md` section 4.

Target: `6.6.58-android15-8-gab1c189b09cf-abogki417154918-4k` (Honor DNN-AN00),
`boot.img` SHA-256
`0c2ef92128301e86fb4ecca5bac772d98cf34f0cd12af2deba0cd84ba279e82b`.

## 1. Why `select_stack` cannot be used on this image

`select_stack` stamps `rt_mutex_waiter` words through the user `fd_set` arrays,
whose 320-bit form gives a 15-word (0..14) window
(`PSELECT_ROUTE_NFDS = 320`; a larger `nfds` moves `core_sys_select` off the
stack). The mapping is `global_word = waiter_shift + table_index`, and the 6.6
table puts `task`/`lock`/`wake_state` at indices 12/13/14.

On this image the stale waiter sits 10 qwords **above** the fd_set window
(`D = 10`), so

| requirement | value |
|---|---|
| `task` (waiter+0x50) lands at | global word 20 |
| placement rule | `12 + waiter_shift = D + 10` → `waiter_shift = D - 2 = +8` |
| window | 0..14 |

`+8` pushes indices 2..14 to 10..22, so `task`/`lock`/`wake_state` land at
20/21/22 - outside the window. Keeping every index inside the window forces
`waiter_shift ∈ [-2, 0]`, which misplaces the three words by 10 qwords (80
bytes). **No `waiter_shift` value makes the full waiter layout expressible**, so
the route is genuinely unavailable here rather than misconfigured.

## 2. The stamping buffer: `__sys_sendmsg`'s on-stack iovec array

`__sys_sendmsg` keeps `UIO_FASTIOV` (8) iovecs in its own frame, zeroes them and
lets `import_iovec`'s fast path copy the user array straight into them (with
`nr_segs <= 8` there is no heap allocation, so the data really is on the kernel
stack).

Evidence, all from `boot.img` disassembly:

| Symbol | Offset | Frame / detail |
|---|---|---|
| `__arm64_sys_sendmsg` | `+0x34bf94` | `stp x29,x30,[sp,#-0x10]!` → frame `0x10`; `bl 0x34bd14` |
| `__sys_sendmsg` | `+0x34bd14` | `sub sp,sp,#0x1d0` → frame `0x1d0`; `0x98: add x0,sp,#0x78` + `memset` `0x80`; `0xb0: add x3,sp,#0x70`; `0xbc: str x24,[sp,#0x70]`; `0xc8: bl 0x34b734` |
| `import_iovec` | `+0x9cd10` | frame `0x60`; `nr_segs = 8 <= fast_segs = 8` → `*iovp` used as the stack array |
| `iovec_from_user` | `+0x345994` | frame `0x40`; `stp x14,x13,[x12]`, 16 bytes per segment |

`__sys_sendmsg` resolves the socket fd (`sockfd_lookup_light`, `f_op ==
socket_file_ops`) **before** the iovec import, so the route must pass a real
socket fd, not a pipe. The iovec bases are never `access_ok`-checked by this
path; the later data copy is expected to fail with `EFAULT`, after the waiter
has already been stamped.

## 3. Waiter geometry (anchor = the stale PI futex waiter)

| Symbol | Frame | Detail |
|---|---|---|
| `__arm64_sys_futex` | `0x80` | `sub sp,sp,#0x80` |
| `futex_wait_requeue_pi` | `0x1c0` | `memset(sp+0x90, 0, 0x70)` → `struct rt_mutex_waiter waiter` at `sp+0x90` (size `0x70`) |

With `SP0` the thread's stack pointer at syscall entry:

```
waiter   = SP0 - 0x80 - 0x1c0 + 0x90 = SP0 - 0x1b0   (size 0x70, ends SP0 - 0x140)
iovstack = SP0 - 0x10 - 0x1d0 + 0x78 = SP0 - 0x168   (size 0x80, ends SP0 - 0x0e8)
```

The buffer therefore covers waiter bytes `[0x48, 0x70)` only - exactly the tail.

### Field mapping

`struct rt_mutex_waiter` from the image BTF (`size = 0x70`):

| Field | Offset | Type |
|---|---|---|
| `tree` | `0x00` | `rt_waiter_node` (0x28) |
| `pi_tree` | `0x28` | `rt_waiter_node` (0x28) |
| `task` | `0x50` | pointer |
| `lock` | `0x58` | pointer |
| `wake_state` | `0x60` | `unsigned int` |
| `ww_ctx` | `0x68` | pointer |

`rt_waiter_node` = `{rb_node entry (0x18); int prio; unsigned long long
deadline}`. **`tree`/`pi_tree` are `rt_waiter_node`, not bare `rb_node`** -
treating them as 0x18 would shift `task` to `0x30` and break the whole mapping.

| iovec byte | user field | waiter offset | field |
|---|---|---|---|
| `0x00` | `iov[0].iov_base` | `0x48` | `pi_tree.deadline` |
| `0x08` | `iov[0].iov_len` | `0x50` | `task` |
| `0x10` | `iov[1].iov_base` | `0x58` | `lock` |
| `0x18` | `iov[1].iov_len` | `0x60` | `wake_state` (low 32 bits) |
| `0x20` | `iov[2].iov_base` | `0x68` | `ww_ctx` |

`iov[3..7]` are written as zero and only rewrite the dead tail above the
waiter.

Stamped values: `pi_tree.deadline = 0`, `task = fake_task`, `lock = fake_lock`,
`wake_state = 3`, `ww_ctx = NULL`.

`tree` (0x00) and `pi_tree` (0x28) are unreachable from this buffer and stay the
live rb nodes. The crafted rb nodes that carry the write target/value live in
the payload page (`fake_w0` / `fake_parent` / `fake_right` / `fake_left`), which
`waiter->lock` redirects the PI walk into - so the stack waiter only has to
supply `task` / `lock` / `wake_state`.

## 4. Remaining risk

1. **The 3-field stamp is an assumption.** The select route on its own device
   overwrites the whole waiter including `tree`/`pi_tree`; whether leaving them
   live is equivalent has not been proven against this image's
   `rt_mutex_adjust_prio_chain`. This is the item to verify before trusting a
   device run.
2. **Trigger ordering.** The route arms the consumer, stamps through `sendmsg()`
   and re-stamps until the consumer reports success. `sendmsg` has no parking
   point, unlike `select`, so the window is bounded by
   `execution.routes.sendmsg_iovec.timeout_us` and by the consumer's own
   `consumer_max_calls` budget.
3. **Untested on hardware.** `kernel_phys_offset` is left `null` (compiled
   `P0_PHYS_OFFSET` default); the profile has not been through the device gate.

## 5. Profile

`app/src/main/assets/kernel_profiles/6.6.58-android15-8-gab1c189b09cf-abogki417154918-4k.conf`,
tuning preset `execution-sendmsg-iovec.conf`. All shared geometry
(`task_struct` 15/15, `offset` 10/10, `cred`, `kernelsnitch`) is unchanged from
the values already verified against this image.

The consumer budget is read from the **active** route's group
(`execution.routes.sendmsg_iovec.consumer_max_calls`), falling back to the
select group - without that, the preset's budget would never reach native and
the consumer would never fire.
