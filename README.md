# GhostLock-App

> 中文: [README_ZH.md](README_ZH.md)

GhostLock matches the running kernel by exact `uname -r` and loads the corresponding HOCON profile. Built-in profiles live in `app/src/main/assets/kernel_profiles/`: one HOCON file per release, `index.conf` as the runtime index, and `<major.minor>-template.conf` version-family templates.

## Documentation

- [Kernel Profile Porting Guide](docs/kernel_profiles/README.md) - profile format, file layout, and kernel matching.
- [Supported devices](docs/kernel_profiles/SUPPORTED_DEVICES.md) - built-in kernel list.
- [Shared execution defaults](docs/kernel_profiles/defaults.md) - every `execution` field and its default.
- [Profile schema](docs/kernel_profiles/PROFILE_SCHEMA.md) - profile structure and data flow.
- [Adding a component](docs/development/adding-a-component.md) - native middleware / backend / frontend (Chinese).

## Build

```powershell
make -C src ghostlock            # native binary -> build/native/ghostlock
./gradlew exportKernelProfiles   # profile binaries -> build/kernel-profiles/
./gradlew :app:assembleDebug     # Android app
```

## Command-line usage

```powershell
adb push build/native/ghostlock /data/local/tmp/ghostlock
adb push build/kernel-profiles/<release>.bin /data/local/tmp/profile.bin
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin
```

## Profile extraction

`tools/extract_rs` derives profile offsets from a `boot.img` (+ optional `xbl_config.img`), a full OTA ZIP, or an `http(s)` URL. kallsyms: `--kallsyms` or the image's embedded table. `pselect_waiter_shift` and `off_slide_loggers_0_1` are derived by the built-in arm64 disassembler. MediaTek images have no `xbl_config.img` and usually no BTF; the physical load address is derived from kallsyms `_text` (override `--phys`).

```powershell
Push-Location tools/extract_rs
cargo build --release
Pop-Location
build/extract/release/ghostlock-extract.exe boot.img --xbl-config xbl_config.img --format conf --out profile.conf
build/extract/release/ghostlock-extract.exe OTA.zip --format conf --out profile.conf
```

`--format conf` writes a flattened, self-contained profile (no `include`; shared constants inlined; route from `--analysis` evidence unless `--route` overrides). It emits each field the image provides and omits the rest; missing or invalid fields are caught by pre-run validation. On 5.x it also derives fields from kernel symbols and BTF. `--format json` is kept for the v1 import path. To add a built-in profile, complete and validate the matching version-family template, save it as a standalone `.conf`, and add it to `kernel_profiles/index.conf`. The old C `offsets.h` registry is deprecated and removed.

### MediaTek

No `xbl_config.img` and usually no embedded BTF: the extractor cannot derive `kernel_phys_load` / `kernel_phys_offset` and leaves them `null`. The runtime falls back to the SoC formula, which does not apply on MediaTek. Run the separate `tools/mtk-phys/` extractor on the device (it reads `/proc/iomem`) and enter the values in the app's advanced overrides. See [MEDIATEK.md](docs/kernel_profiles/MEDIATEK.md).

### Preflight

The extractor runs a preflight check on the image before extracting offsets. Images that fail it are rejected with exit code `6`.

### On-device analysis

A full OTA can be analyzed on the phone: `boot` + `xbl_config` are extracted automatically. Pass `--work-dir` an app-writable dir when running inside the app sandbox. Cross-compile and push:

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

### Importing offsets without rebuilding the app

**Import offsets.conf (HOCON)** takes the extractor's flattened `.conf`; **Import offsets.json (v1)** takes an older JSON report, converted in-app. Imports merge across files; an existing release prompts before overwrite.

**Parse OTA link** (full OTA ZIP URL) and **Parse image** (`boot.img` + optional `xbl_config.img`) run the extractor in-process and write a flattened `.conf` into the app data dir:

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

## Credits & license

Based on the following projects, Apache License 2.0 ([LICENSE](LICENSE)):

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus)
