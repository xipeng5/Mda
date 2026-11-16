# 验收探针（真机 ground truth，非模拟）

三个探针都是**在真机上跑出来的原始事实**，不是推断。编译用 NDK 27（22 也可）：

```bash
NDK=~/Library/Android/sdk/ndk/27.1.12297006/toolchains/llvm/prebuilt/darwin-x86_64/bin
$NDK/aarch64-linux-android21-clang++ -O1 -fPIE -pie -static-libstdc++ -o container_probe container_probe.cpp
$NDK/aarch64-linux-android21-clang  -O1 -fPIE -pie -o hold_target hold_target.c
$NDK/aarch64-linux-android21-clang++ -O1 -fPIE -pie -static-libstdc++ -o sso_boundary sso_boundary.c
adb -s 3e2ff172 push <bin> /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/<bin>
```

| 探针 | 用途 | 已知坑 |
|---|---|---|
| `container_probe.cpp` | 取 libc++ 容器真实内存布局（string/vector/map） | 必须用 NDK 27+（Android 21 ABI 有 TLS 对齐问题，详见下） |
| `sso_boundary.c` | 扫出 SSO 边界（0..32 字符）与首字节 flag | 同上 |
| `hold_target.c` | hold 断点靶子：每 200ms 调一次 `work()` | 静态链接版在 Android 12 上会因 TLS 段对齐 8<64 被 linker 拒绝，**必须动态链接** |

## Android 12 (API 31) 部署约束（实测）

1. **静态链接不可用**：`error: "…": executable's TLS segment is underaligned: alignment is 8 (skew 0), needs to be at least 64 for ARM64 Bionic` → 用 `-fPIE -pie` 动态链接。
2. **NDK 21.0.6113669 的 clang++ 在本机被 SIGKILL**（`Killed: 9`），改用 NDK 27.1.12297006 正常。
3. `nohup … &` 直接放在 `adb shell "…"` 里会因 shell 退出被杀；要用 `( nohup … & )` 或 `nohup sh -c '…' &` 的括起形式。

## 为什么探针源码要留在仓库

`read_std_container` 的期望值（SSO 22 字符边界、long flag 在第 0 字节最低位、`__long` 成员顺序 cap/size/data）全部来自
这两个探针的**实测输出**。把它们留在仓库里，任何人可以重跑得到同样数字，而不是照着 libc++ 头文件"推导"一个可能错的结论。
