#include "route/sendmsg_iovec_route.h"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <type_traits>
#include <utility>

using namespace ghostlock;

int32_t main(void) {
    ghostlock::race::PiRace race;
    assert(race.reset(0, 0, 1));
    ghostlock::memory::WriteRequest request{};
    const profile::TargetProfile profile{};

    ghostlock::route::sendmsg_iovec::SendmsgIovecRoute context(&race, &request, profile);
    assert(context.race == &race && context.request == &request);
    assert(&context.profile == &profile);
    assert(!context.sock_read.valid() && !context.sock_write.valid());
    assert(context.consumer_stuck == 0 && context.stamps == 0);
    assert(context.status.code == ghostlock::route::ROUTE_RETRYABLE);

    /* The on-stack iovec array must be exactly UIO_FASTIOV segments: one more
     * would move import_iovec onto the heap and off the target stack. */
    assert(ghostlock::route::sendmsg_iovec::kSendmsgFastIovCount == 8);

    /* Move-only: the socketpair and the counters travel with the move. */
    static_assert(!std::is_copy_constructible_v<
                  ghostlock::route::sendmsg_iovec::SendmsgIovecRoute>);
    static_assert(!std::is_copy_assignable_v<
                  ghostlock::route::sendmsg_iovec::SendmsgIovecRoute>);
    static_assert(std::is_move_constructible_v<
                  ghostlock::route::sendmsg_iovec::SendmsgIovecRoute>);
    {
        ghostlock::route::sendmsg_iovec::SendmsgIovecRoute source(&race, &request, profile);
        int32_t fds[2];
        assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
        source.sock_read.reset(fds[0]);
        source.sock_write.reset(fds[1]);
        source.stamps = 7;
        source.calls = 3;
        source.successes = 2;
        ghostlock::route::sendmsg_iovec::SendmsgIovecRoute moved(std::move(source));
        assert(moved.sock_read.get() == fds[0]);
        assert(!source.sock_read.valid());
        assert(moved.sock_write.get() == fds[1]);
        assert(moved.stamps == 7 && moved.calls == 3 && moved.successes == 2);
        moved.destroy();
        assert(!moved.sock_read.valid() && !moved.sock_write.valid());
        assert(fcntl(fds[0], F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(fds[1], F_GETFD) == -1 && errno == EBADF);
        assert(moved.status.userspace_clean == 1);
    }

    /* A stuck consumer retains every route descriptor for process lifetime. */
    {
        ghostlock::route::sendmsg_iovec::SendmsgIovecRoute stuck(&race, &request, profile);
        int32_t fds[2];
        assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) == 0);
        stuck.sock_read.reset(fds[0]);
        stuck.sock_write.reset(fds[1]);
        stuck.send_errno = 9;
        stuck.consumer_stuck = 1;
        stuck.destroy();
        assert(stuck.status.code == ghostlock::route::ROUTE_DIRTY_FAILURE);
        assert(stuck.status.step == 45);
        assert(stuck.status.error_number == 9);
        assert(!stuck.sock_read.valid() && !stuck.sock_write.valid());
        assert(fcntl(fds[0], F_GETFD) != -1);
        assert(fcntl(fds[1], F_GETFD) != -1);
        close(fds[0]);
        close(fds[1]);
    }

    /* disarm is idempotent and marks the route disarmed. */
    context.disarm();
    context.disarm();
    assert(context.status.kernel_disarmed == 1);
    assert(race.consumer_go.load() == 0);

    /* destroy without resources is idempotent and reports a clean fallback. */
    context.destroy();
    context.destroy();
    assert(context.status.userspace_clean == 1);
    assert(context.status.code == ghostlock::route::ROUTE_FALLBACK_SAFE);

    /* fail() records step and errno for the caller's log. */
    assert(context.fail(59, 5) == -1);
    assert(context.status.step == 59);
    assert(context.status.error_number == 5);

    puts("sendmsg_iovec_route_test: ok");
    return 0;
}
