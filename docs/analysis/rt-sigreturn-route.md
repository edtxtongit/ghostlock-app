# `rt_sigreturn` middleware — static analysis (6.6.58 DNN-AN00)

**Image:** `6.6.58-android15-8-gab1c189b09cf-abogki417154918-4k` (Honor DNN-AN00)
**Scope:** static, image-only. No device run, no pstore. Device behaviour is **not**
verified; this route is not listed as a supported device yet.

> **Status: NOT VIABLE — do not enable on device.** The route's trigger premise
> is refuted by the target image: `pi_blocked_on` (offset `0x938`) is cleared on
> every normal return path of `FUTEX_WAIT_REQUEUE_PI`, and that syscall returns
> before this route runs. See §5.1. The stack-overlap geometry is real but cannot
> restore the cleared task pointer, so the route cannot drive the PI chain walk.

## 1. Why the earlier routes do not fit this image

- `select_stack`: the stale `rt_mutex_waiter` sits 10 qwords above the pselect
  fd_set window. The PI walk consumes waiter words 10..12 (task/lock/wake_state);
  placing them needs `waiter_shift = +8`, which lands them at global words
  20/21/22 — past the 15-word fd_set window. Staying inside the window
  misplaces them by 10 qwords. No `waiter_shift` works.
- `sendmsg_iovec`: with the payload this route needs, `iov[0].iov_len` carries
  the high-half `fake_task`, so `import_iovec`'s bit-63 check returns `-EINVAL`
  before `iov[1].iov_base` (waiter->lock) is ever stored. The overlapping stack
  area is additionally zeroed before the import, but the earlier length check is
  the first failure, not `access_ok`. **This route is unusable and is not used by
  the DNN-AN00 profile.**

## 2. Image facts

`__arm64_sys_rt_sigreturn` @ payload `+0x414af4`:

```
stp x29, x30, [sp, #-0x60]!     ; entry frame 0x60
sub sp, sp, #0x270              ; local frame 0x270   => D = 0x2d0
...
memset(sp + 0x50, 0, 0x210)     ; clear the signal save area
cmp  wsize, #0x210              ; FPSIMD record size gate
...
add  x0, sp, #0x50              ; dest = kernel stack buffer
mov  w2, #0x200                 ; length = FPSIMD vregs
bl   __arch_copy_from_user      ; @ +0x415138, source = record + 0x10
```

The FPSIMD signal record is the first record in `sigcontext.__reserved`:

| field | value |
|---|---|
| magic | `0x46508001` |
| size | `0x210` |
| `vregs[32]` | offset `0x10`, 16 bytes each |

The copied range is the 0x200-byte `vregs` array (`record + 0x10`); the 8-byte
record header and the FPSR/FPCR pair are parsed/validated, so "unvalidated"
applies only to the copied vector payload, not to the whole 0x210-byte record.
There is **no `capable()`/LSM gate** on this path. The FPSIMD branch requires
`system_cpucaps[36] == 0` (`has_no_fpsimd` absent), which holds on any CPU with
the FPSIMD feature — i.e. the normal arm64 case; the value cannot be read from a
static image and is a documented profile condition.

## 3. Geometry (relative to syscall entry `SP0`)

Futex frames (same as the other routes):

| object | address |
|---|---|
| `__arm64_sys_futex` frame | `0x80` |
| `futex_wait_requeue_pi` frame | `0x1c0` |
| waiter local (`sp+0x90` in that frame) | `SP0 - 0x1b0` |

`rt_sigreturn` buffer: `D - O = 0x2d0 - 0x50 = 0x280` from `SP0`, length
`0x200`. The waiter spans `[SP0-0x1b0, SP0-0x140)`, so the buffer **fully
contains** the waiter and covers the whole head, not just the tail:

| waiter field | waiter off | copy off | vreg |
|---|---:|---:|---:|
| tree | `0x00` | `0x0d0` | `v13` |
| pi_tree | `0x28` | `0x0f8` | `v15` |
| task | `0x50` | `0x120` | `v18.d[0]` |
| lock | `0x58` | `0x128` | `v18.d[1]` |
| wake_state | `0x60` | `0x130` | `v19.d[0]` |
| ww_ctx | `0x68` | `0x138` | `v19.d[1]` |

`rt_mutex_waiter` is `0x70` bytes (`tree`/`pi_tree` are `rt_waiter_node`,
`0x28` each). The copy reaches `0x130..0x140` as well, so this route defines
**all** of `v13..v19`; nothing above the waiter is left live.

## 4. Route mechanics

Per stamp the waiter thread sets `v13..v19` and issues
`tgkill(getpid(), gettid(), SIGURG)` from a single `asm` block, so no compiler
code can clobber the vector registers before the syscall. The signal is
unblocked and a no-op handler installed; the kernel builds the signal frame from
the current vector state, the handler returns through `rt_sigreturn`, and the
`__arch_copy_from_user` above writes the vregs onto the kernel stack over the
stale waiter. The consumer thread then fires `sched_setattr` on the waiter TID,
walking the PI chain.

`wake_state` is set to `3` = `TASK_NORMAL`
(`TASK_INTERRUPTIBLE|TASK_UNINTERRUPTIBLE`), matching what the image's own
`futex_wait_requeue_pi` installs on its stack waiter. `3` is **not** an rt_mutex
chainwalk enum: `RT_MUTEX_FULL_CHAINWALK` is the chainwalk code `1`, not a
waiter `wake_state`.

The crafted rb nodes that carry the write target/value live in the payload page
that `waiter->lock` redirects the walk into (`prepare_skb_payload`), so the stack
waiter only has to carry `task`/`lock`/`wake_state`. The head (`tree`/`pi_tree`)
is written as a zero rb node; under Linux rbtree semantics a zero node is **not**
`RB_EMPTY_NODE` (`__rb_parent_color == (unsigned long)node` is required), so the
walk treats it as a real `parent=left=right=0, black` node and the erase/relink
of that topology is load-bearing, not a no-op. The resulting write is conditional
on the forged parent's `rb_left` comparison, and `waiter_clone_prio` asserts the
`pi_tree` is empty under `CONFIG_LOCKDEP` (target config unknown). This is a
structural argument from android15-6.6 common, not a target-image or on-device
proof. It is also **not byte-identical** to `select_stack`, which writes `1`
into the ordering field where this route writes `0`; whether the two converge
depends on the later PI re-sort.

## 5. Caveats (unproven)

### 5.1 `pi_blocked_on` — the route's premise is refuted (verified on the image)

The route only works if `current->pi_blocked_on` (`[x, #0x938]`) still points at
the stale waiter when the consumer fires. The target image clears that field
before the route can run:

| site | image evidence | effect |
|---|---|---|
| `0x108b008` (`rt_mutex_wait_proxy_lock` acquire path) | `str xzr, [x20, #0x938]` | clears before the acquire completes |
| `0x108b818` (inside `remove_waiter` @ `0x108b790`, reached by cleanup when the waiter is not the owner) | `str xzr, [x20, #0x938]` | clears |
| `0x108bf78` / `0x108bf7c` (`rt_mutex_adjust_prio_chain`) | `ldr x25, [x19, #0x938]` ; `cbz x25, ...` | a zero pointer exits the walk |

`0x938 = 2360` is exactly the profile's `task_struct.pi_blocked_on` offset, so the
disassembly field matches the profile. `waiter_thread()` calls the route only
**after** `FUTEX_WAIT_REQUEUE_PI` returns. In the expected timing the owner holds
`target_futex` until the route is done, so the waiter cannot acquire the lock and
must return through the timeout/error path → `rt_mutex_cleanup_proxy_lock` →
`remove_waiter` → the clear at `0x108b818`. By the time the route stamps and arms
the consumer, `pi_blocked_on` is already zero, and `sched_setattr(waiter_tid)`
cannot walk the stale stack waiter. This is an static image + source-order
conclusion, **not** a device run.

- Consequence: the FPSIMD stack-overlap geometry (§3, §4) can be correct without
  the route doing anything, because the task-field link that starts the walk is
  gone. This branch must not be enabled or marked supported until a trigger that
  keeps `pi_blocked_on` live is found and proven.
- Stamp/consumer handshake: the route now stamps **exactly once** and only then
  arms the consumer, so no second `rt_sigreturn` `memset`+copy can race the
  consumer's check-then-use of `waiter->lock`. The max-call failure branch also
  waits for `consumer_inflight == 0` and re-reads success, so it cannot fail a
  consumer call that is still in flight. This removes the re-stamp and
  premature-max-call races but does not prove the consumer reads the stamped
  waiter. A profile with no max-call budget and no timeout is bounded by an
  internal spin cap.
- `disarm()` stops the consumer and reports userspace cleanliness only. It does
  **not** clear the stale waiter or `task->pi_blocked_on`, so the route never
  claims `kernel_disarmed` and a clean non-OK outcome is never
  `ROUTE_FALLBACK_SAFE`.
- Not device-verified; no pstore/ramoops. `kernel_phys_offset = null` uses the
  compiled default and is untested on this unit.
- The FPSIMD branch condition (`system_cpucaps[36] == 0`) is a runtime CPU feature
  bit, not statically decidable from the image.

## 6. Profile

`app/src/main/assets/kernel_profiles/6.6.58-android15-8-gab1c189b09cf-abogki417154918-4k.conf`
currently selects `route { rt_sigreturn { } }` with `fallback { to = "none" }`;
execution tuning is `execution-rt-sigreturn.conf`. Per §5.1 this selection is
**not viable** and must not be treated as a working device profile.
