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

## Profile 提取

`tools/extract_rs` 从 `boot.img`（可加 `xbl_config.img`）、完整 OTA zip 或指向它的 `http(s)` 链接解析 profile 偏移量。kallsyms 传 `--kallsyms`，或取镜像内嵌表。`pselect_waiter_shift` 与 `off_slide_loggers_0_1` 由内置 arm64 反汇编器推导。联发科镜像没有 `xbl_config.img` 且通常无内嵌 BTF：物理加载地址由 kallsyms `_text` 推导（可用 `--phys` 覆盖）。

```powershell
Push-Location tools/extract_rs
cargo build --release
Pop-Location
build/extract/release/ghostlock-extract.exe boot.img --xbl-config xbl_config.img --format conf --out profile.conf
build/extract/release/ghostlock-extract.exe OTA.zip --format conf --out profile.conf
```

`--format conf` 写出 flatten、自包含 profile（无 `include`；共享常量内联；route 由 `--analysis` 证据建议，`--route` 可覆盖）。写出镜像实际提供的字段，其余省略；缺失或无效字段由运行前校验拦截。5.x 还会从内核符号与 BTF 推导额外字段。`--format json` 保留给 v1 导入路径。新增内置配置：以对应大版本模板补齐并验证字段，另存为独立 `.conf`，登记到 `kernel_profiles/index.conf`。旧 C `offsets.h` 注册表已弃用并移除。

### 联发科

无 `xbl_config.img`，通常也无内嵌 BTF：提取器无法推导 `kernel_phys_load` / `kernel_phys_offset`，留 `null`。运行时回退到 SoC 公式，在联发科上不适用。在设备上运行 `tools/mtk-phys/`（读取 `/proc/iomem`），把值填入 App 高级参数覆盖。参见 [MEDIATEK_ZH.md](docs/kernel_profiles/MEDIATEK_ZH.md)。

### 前置检查

提取器在提取偏移量前对镜像做一次前置检查；未通过的镜像以退出码 `6` 拒绝。

### 手机端运行

完整 OTA 可在手机上分析：自动提取 `boot` + `xbl_config`。App 沙箱内运行时 `--work-dir` 须指向 App 可写目录。交叉编译后 push：

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
adb shell /data/local/tmp/ghostlock-extract /sdcard/OTA.zip
```

### 外部导入偏移，免重建应用

**导入 offsets.conf (HOCON)** 选择提取器产出的扁平 `.conf`；**导入 offsets.json (v1)** 选择旧 JSON 报告，v1 JSON 由 App 侧转换。多次导入合并；已存在的 release 会先询问是否覆盖。

**解析完整包链接**（完整 OTA zip 的 `http(s)` 链接）与**解析镜像**（`boot.img` + 可选 `xbl_config.img`）在 App 进程内跑提取器，成功后把扁平 `.conf` 写入 App 数据目录：

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
