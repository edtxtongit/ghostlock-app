#include "route/rt_sigreturn_route.h"

#include "route/rt_sigreturn_layout.h"

#include <cassert>
#include <cstdint>
#include <cstdio>

#include <type_traits>
#include <utility>

using namespace ghostlock;
namespace layout = ghostlock::route::rt_sigreturn;

int32_t main(void) {
    ghostlock::race::PiRace race;
    assert(race.reset(0, 0, 1));
    ghostlock::memory::WriteRequest request{};
    const profile::TargetProfile profile{};

    ghostlock::route::rt_sigreturn::RtSigreturnRoute context(&race, &request,
                                                             profile);
    assert(context.race == &race && context.request == &request);
    assert(&context.profile == &profile);
    assert(context.action_installed == 0 && context.mask_installed == 0);
    assert(context.consumer_stuck == 0 && context.stamps == 0);
    assert(context.status.code == ghostlock::route::ROUTE_RETRYABLE);

    /* Kernel geometry measured on the target image. */
    static_assert(layout::kKernelFrameDepth == 0x2d0);
    static_assert(layout::kKernelBufferFrameOffset == 0x50);
    static_assert(layout::kKernelBufferStart == 0x280);
    static_assert(layout::kKernelMemsetLength == 0x210);
    static_assert(layout::kKernelCopyLength == 0x200);

    /* Stale waiter coordinate (futex_wait_requeue_pi frame + sp+0x90). */
    static_assert(layout::kWaiterTaskFromSp0 == 0x160);
    static_assert(layout::kWaiterLockFromSp0 == 0x158);
    static_assert(layout::kWaiterWakeStateFromSp0 == 0x150);
    static_assert(layout::kWaiterTreeFromSp0 == 0x1b0);
    static_assert(layout::kWaiterPiTreeFromSp0 == 0x188);

    /* Buffer offsets of the fields the PI walk consumes. */
    static_assert(layout::kTaskCopyOffset == 0x120);
    static_assert(layout::kLockCopyOffset == 0x128);
    static_assert(layout::kWakeStateCopyOffset == 0x130);
    static_assert(layout::kWwCtxCopyOffset == 0x138);
    static_assert(layout::kTreeCopyOffset == 0x0d0);
    static_assert(layout::kPiTreeCopyOffset == 0x0f8);
    static_assert(layout::kWaiterCopyBytes == 0x70);

    /* Vector-register lanes the fields land in. */
    static_assert(layout::kTaskVreg == 18 && layout::kTaskHalf == 0);
    static_assert(layout::kLockVreg == 18 && layout::kLockHalf == 1);
    static_assert(layout::kWakeVreg == 19 && layout::kWakeHalf == 0);
    static_assert(layout::kWwCtxVreg == 19 && layout::kWwCtxHalf == 1);
    static_assert(layout::kFirstWaiterVreg == 13);
    static_assert(layout::kLastWaiterVreg == 19);
    static_assert(layout::kWakeStateValue == 3);

    /* Move-only: the counters and signal state travel with the move. */
    static_assert(!std::is_copy_constructible_v<
                  ghostlock::route::rt_sigreturn::RtSigreturnRoute>);
    static_assert(!std::is_copy_assignable_v<
                  ghostlock::route::rt_sigreturn::RtSigreturnRoute>);
    static_assert(std::is_move_constructible_v<
                  ghostlock::route::rt_sigreturn::RtSigreturnRoute>);
    {
        ghostlock::route::rt_sigreturn::RtSigreturnRoute source(&race, &request,
                                                                profile);
        source.action_installed = 1;
        source.mask_installed = 1;
        source.stamps = 11;
        source.calls = 4;
        source.successes = 1;
        ghostlock::route::rt_sigreturn::RtSigreturnRoute moved(
            std::move(source));
        assert(moved.action_installed == 1 && moved.mask_installed == 1);
        assert(moved.stamps == 11 && moved.calls == 4 && moved.successes == 1);
    }

    /* disarm is idempotent and stops the consumer, but never claims the stale
     * waiter / pi_blocked_on was cleared. */
    context.disarm();
    context.disarm();
    assert(context.status.kernel_disarmed == 0);
    assert(race.consumer_go.load() == 0);

    /* destroy without a stuck consumer reports clean userspace only: no kernel
     * disarm, so a clean non-OK outcome stays retryable and not fallback-safe. */
    context.destroy();
    context.destroy();
    assert(context.status.userspace_clean == 1);
    assert(context.status.code == ghostlock::route::ROUTE_RETRYABLE);
    assert(!context.status.can_fallback());

    /* A stuck consumer is a dirty failure with its own step. */
    {
        ghostlock::route::rt_sigreturn::RtSigreturnRoute stuck(&race, &request,
                                                               profile);
        stuck.stamp_errno = 7;
        stuck.consumer_stuck = 1;
        stuck.destroy();
        assert(stuck.status.code == ghostlock::route::ROUTE_DIRTY_FAILURE);
        assert(stuck.status.step == 47);
        assert(stuck.status.error_number == 7);
    }

    /* fail() records step and errno for the caller's log. */
    assert(context.fail(59, 5) == -1);
    assert(context.status.step == 59);
    assert(context.status.error_number == 5);

    puts("rt_sigreturn_route_test: ok");
    return 0;
}
