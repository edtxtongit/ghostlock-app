# GhostLock-App

> English: [README.md](README.md)

GhostLock 通过精确 `uname -r` 匹配当前内核并加载对应 HOCON profile。内置配置位于 `app/src/main/assets/kernel_profiles/`：每个 release 一个 HOCON 文件，`index.conf` 运行索引，`<major.minor>-template.conf` 大版本模板。

## 文档

- [Kernel Profile 适配指南](docs/kernel_profiles/README_ZH.md) —— profile 格式、文件布局与内核匹配。
- [支持设备列表](docs/kernel_profiles/SUPPORTED_DEVICES_ZH.md) —— 内置内核清单。
- [公共执行默认值](docs/kernel_profiles/defaults_ZH.md) —— 每个 `execution` 字段的默认值。
- [Profile 结构文档](docs/kernel_profiles/PROFILE_SCHEMA_ZH.md) —— profile 结构与数据流。
- [新增组件指南](docs/development/adding-a-component.md) —— native middleware / backend / frontend。

## 构建

```powershell
make -C src ghostlock            # native 产物 -> build/native/ghostlock
./gradlew exportKernelProfiles   # profile 产物 -> build/kernel-profiles/
./gradlew :app:assembleDebug     # Android App
```

## 命令行使用

```powershell
adb push build/native/ghostlock /data/local/tmp/ghostlock
adb push build/kernel-profiles/<release>.bin /data/local/tmp/profile.bin
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin
```

## Profile 提取（独立工具）

`tools/extract_rs` 是独立命令行程序；Android App 不会解析镜像、payload、OTA 包或 OTA 链接。请在 App 外运行提取器（在电脑上运行，或手动交叉编译成 Android 独立二进制后运行），生成 profile 文件，再导入 GhostLock。工具可从 `boot.img`（可加 `xbl_config.img` / `uefi.img`）、完整 OTA zip 或 `http(s)` 链接推导 profile 偏移量。kallsyms 传 `--kallsyms`，或使用镜像内嵌表。`pselect_waiter_shift` 与 `off_slide_loggers_0_1` 由内置 arm64 反汇编器推导。联发科镜像没有 `xbl_config.img` 且通常无内嵌 BTF：物理加载地址由 kallsyms `_text` 推导（可用 `--phys` 覆盖）。

```powershell
Push-Location tools/extract_rs
cargo build --release
Pop-Location
build/extract/release/ghostlock-extract.exe boot.img --xbl-config xbl_config.img --format conf --out profile.conf
build/extract/release/ghostlock-extract.exe OTA.zip --format conf --out profile.conf
# 也可传入 OTA URL，而非本地压缩包：
build/extract/release/ghostlock-extract.exe "https://example.invalid/update.zip" --format conf --out profile.conf
```

`--format conf` 写出扁平、自包含 profile（无 `include`；共享常量内联；route 由 `--analysis` 证据建议，`--route` 可覆盖）。只写出镜像实际提供的字段，其余省略；缺失或无效字段由运行前校验拦截。5.x 还会从内核符号与 BTF 推导额外字段。`--format json` 保留给旧版 v1 导入路径。新增内置配置：以对应大版本模板补齐并验证字段，另存为独立 `.conf`，登记到 `kernel_profiles/index.conf`。旧 C `offsets.h` 注册表已弃用并移除。

### 联发科

无 `xbl_config.img`，通常也无内嵌 BTF：提取器无法推导 `kernel_phys_load` / `kernel_phys_offset`，留 `null`。运行时回退到 SoC 公式，在联发科上不适用。在设备上运行单独的 `tools/mtk-phys/`（读取 `/proc/iomem`），把值填入 App 高级参数覆盖。参见 [MEDIATEK_ZH.md](docs/kernel_profiles/MEDIATEK_ZH.md)。

### 前置检查

独立提取器会在提取偏移量前检查镜像；未通过的镜像以退出码 `6` 拒绝。

### 可选：在 Android 上运行独立提取器

这是手动命令行流程，不是 App 功能。交叉编译独立 Rust 可执行文件、推送到设备后，从 shell 手动运行，并把生成的 profile 写入可访问位置（例如 Downloads）：

```powershell
rustup target add aarch64-linux-android
$ndk = "$env:ANDROID_HOME\ndk\<version>\toolchains\llvm\prebuilt\windows-x86_64\bin"
$env:CC_aarch64_linux_android = "$ndk\aarch64-linux-android35-clang.cmd"
$env:AR_aarch64_linux_android = "$ndk\llvm-ar.exe"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $env:CC_aarch64_linux_android
Push-Location tools/extract_rs
cargo build --release --target aarch64-linux-android
Pop-Location
adb push build/extract/aarch64-linux-android/release/ghostlock-extract /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock-extract
adb shell /data/local/tmp/ghostlock-extract /sdcard/OTA.zip --format conf --out /sdcard/Download/profile.conf
```

### 在 App 中导入生成的 profile

在 GhostLock 中打开 **高级 → 加载配置**，对独立提取器生成的 `.conf` 选择 **导入 offsets.conf (HOCON)**。旧版 JSON 报告仍可使用 **导入 offsets.json (v1)**。若 profile 使用了 include 依赖文件，请在文档选择器中同时选中 profile 和这些依赖文件。若某 release 的偏移已存在，App 会先询问是否覆盖。提取器输出以文件方式导入；App 不会启动提取器，也不会自行下载或处理 OTA 内容。

独立提取器输出的 HOCON 示例：

```hocon
# GhostLock profile: 6.12.38-android16-5-g844001fb8721-ab14552068-4k (HOCON, self-contained).
release = "6.12.38-android16-5-g844001fb8721-ab14552068-4k"
schema_version = 1
kernel_major = 6
kernel_phys_load = 0xC7800000
route {
  select_stack {
    waiter_shift = 0
  }
}
fallback {
  to = "none"
}
```

## 来源与许可证

基于以下项目改写，继承 Apache License 2.0（见 [LICENSE](LICENSE)）：

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
