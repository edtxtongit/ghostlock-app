# 静态核对题：内核栈帧复用 —— rt_sigreturn 栈写入与 PI waiter 字段对应关系

本题只做静态核对，可用材料仅 `boot.img` 与 `gl_dis.py`。

## 材料

- `/workspace/boot.img`
  - 大小 `100,663,296` B
  - SHA-256 `0c2ef92128301e86fb4ecca5bac772d98cf34f0cd12af2deba0cd84ba279e82b`
  - arm64 Image payload `36,911,616` B @ file offset `0x1000`
- `/workspace/gl_dis.py`
  - 用法：`python3 gl_dis.py <label> <payload_hexoff> <n>`
  - Capstone 反汇编 payload 偏移

无源码、无真机、无其他文件。

## 给定锚点（payload 偏移，已核实，可引用）

| 符号 | payload 偏移 |
|---|---|
| `__arm64_sys_futex` | `0x15ef18` |
| `futex_wait_requeue_pi` | `0x8c22ac` |
| `remove_waiter` | `0x108b790` |
| `rt_mutex_adjust_prio_chain` | `0x108bf04`（读取入口 `0x108bf78`） |
| `__arm64_sys_rt_sigreturn` | `0x414af4`（拷贝点 `0x415138`） |
| `task_struct.pi_blocked_on` | `0x938` |

`rt_mutex_waiter` 布局：`tree 0x00 / pi_tree 0x28 / task 0x50 / lock 0x58 /
wake_state 0x60 / ww_ctx 0x68 / size 0x70`。

## 参考调用序列（按此假设发生，无需读 app 源码）

- **W 线程**：`FUTEX_LOCK_PI(chain)`；然后
  `FUTEX_WAIT_REQUEUE_PI(wait, timeout, target)` 挂起。
- **O 线程**：`FUTEX_LOCK_PI(target)`；然后 `FUTEX_LOCK_PI(chain)`
  （被 W 持有的 `chain` 挡住）。
- **M 线程**：`futex(wait, FUTEX_CMP_REQUEUE_PI, 1, 1, target, 0)`。
- **W 线程**从 `FUTEX_WAIT_REQUEUE_PI` 返回后，在同一线程内：
  - 装 `SIGURG` 处理函数；
  - 把向量寄存器设为 `v13..v17 = 0`，`v18.d[0] = task`、`v18.d[1] = lock`，
    `v19.d[0] = 3`、`v19.d[1] = 0`；
  - `tgkill(getpid(), gettid(), SIGURG)` 打一次信号，使本线程执行一次
    `__arm64_sys_rt_sigreturn`。
- **C 线程**：循环 `sched_setattr(W 的 tid, nice=19 / SCHED_BATCH)`。

## 已核实几何（可直接引用，不必重推）

- `futex_wait_requeue_pi` 的 waiter @ `SP0-0x1b0`。
- `__arm64_sys_rt_sigreturn` 帧 `0x2d0`，拷贝 `0x200` 字节到 `sp+0x50`，
  即缓冲 @ `[SP0-0x280, SP0-0x80)`，完整包含上述 waiter。
- 拷贝内偏移：`tree 0xd0 / pi_tree 0xf8 / task 0x120 / lock 0x128 /
  wake_state 0x130 / ww_ctx 0x138`。

## 需要核对的（只有 3 项）

### C1 — `-EDEADLK` 返回路径存在性

镜像 `futex_requeue` 的 PI 分支在出现 PI 依赖等待环时返回 `-EDEADLK`，
且该分支确实调用 `remove_waiter(lock, waiter)`。结合上面 W/O/M 的持锁顺序，
说明是否需要额外条件才会走到。

依据：相关指令地址。

### C2 — 字段写入对象与后续写入核对 ★ 主要

- (a) 该调用里写 `pi_blocked_on` 的那条 store（`0x108b818`）用的是
  `current` 还是 `waiter->task`？说明 `current` 与 `waiter->task`
  是否同一对象。
- (b) 从该回退点起，到 W 的 futex 调用返回用户态为止，穷举所有对
  `<某 task>+0x938` 的 store，核对没有一条写的是 `waiter->task` 的字段。

依据：写入点清单（地址 + 写入对象）。

若存在任何一条写 waiter 字段的 store → 结论：不一致，到此结束。

### C3 — 读取路径可达性

`sched_setattr(W 的 tid)` 在本镜像走到 `rt_mutex_adjust_prio_chain`，
且 `0x108bf78` 的 `ldr x25,[x19,#0x938]` / `cbz` 在这条路径上被读取、
非零时继续；该 waiter 正是上面拷贝覆盖的那个。

依据：`sched_setattr` 路径与 `0x108bf78` 的指令链。

## 结论口径

- `C1 ∧ C2 ∧ C3` 全过 → **一致（静态）**
- 任一项不成立 → **不一致**
- 证据不足以下结论 → **无法判定**

另需说明每项的否定条件是否出现。

## 交付格式

```
C1: 结论 / 指令地址(payload 偏移) / 依据 / 否定条件是否出现
C2: 同上，附写入点清单
C3: 同上
结论：一致 / 不一致 / 无法判定
```

## 不在本题范围（由其他环节处理，不要展开）

物理地址常量、CPU feature 位、真机运行 —— 都不需要在这题里核对。
