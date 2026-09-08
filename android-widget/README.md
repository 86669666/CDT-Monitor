# CDT Monitor Android 小组件

这是基于 CDT Monitor 小组件 API 的原生 Android 实验项目，目前先随主仓库保存，供后续研究和完善，不作为稳定客户端正式发布。它只调用已经提供的只读接口：

```text
GET /api/v1/widget/summary
Authorization: Bearer <API Key>
```

## 使用方式

1. 在 CDT Monitor Web 控制台的“设置 → API Key”创建一个只包含 `widget:read` 的 Key。Key 只显示一次。
2. 安装应用并打开“CDT Monitor 小组件”，填写站点地址和 Key，点击“保存并测试连接”。
3. 在 Android 桌面添加“CDT Monitor 实例”小组件。
4. 在配置页选择要显示的实例，点击“添加小组件”。

应用会按 Android 小组件的系统刷新周期更新状态，并设置一个不早于 30 分钟的非精确定时刷新。点击小组件可打开连接设置。小组件只保存选中的实例 ID；站点地址明文保存，API Key 使用 Android Keystore 加密后保存。

站点地址可以是 `http://` 或 `https://`，但公网部署必须使用 HTTPS，避免 API Key 在网络中暴露。

## 本地构建

需要 JDK 17、Android SDK 35。Gradle 由仓库内 Wrapper 固定为 8.10.2，不要依赖宿主机 `gradle`：

```bash
cd android-widget
./gradlew assembleRelease bundleRelease
```

### 本机工具链（ops writer host）

检查时间：2026-09-08 04:50 Asia/Taipei（`2026-09-07T20:50Z`）。这台 ops 工作区 **不能** 本地出包，不要把本机未构建写成 APK 已验证。

| 依赖 | 本机状态 |
| --- | --- |
| JDK 17 / `java` / `javac` | 不存在，`JAVA_HOME` 为空 |
| Android SDK 35 / `sdkmanager` / `adb` | 不在 PATH |
| Gradle 8.10.2 | 不在 PATH；改用仓库 `./gradlew`（Wrapper 8.10.2，checksum 已钉死，`org.gradle.daemon=false`，`org.gradle.workers.max=2`） |
| Gradle Wrapper | 已加入 `gradlew` / `gradle-wrapper.jar`；本机仍缺 JDK，所以 **没有** 跑过 `./gradlew` |

因此本机出包仍是 blocker（缺 JDK/SDK），不要把 Wrapper 入库写成 APK 已验证。支持的构建路径仍是手动触发 `.github/workflows/android-widget.yml`（现改为 `./gradlew`）。签名密钥只通过 Actions secrets 注入，keystore 不要进 git。

产物位于 `app/build/outputs/`：

- `apk/debug/*universal*.apk`：可直接安装的通用 debug APK。
- `apk/release/*universal*.apk`、`*arm64-v8a*.apk`、`*armeabi-v7a*.apk`、`*x86*.apk`：通用与常见 ABI 分包（未签名时文件名会带 `-unsigned`）。
- `bundle/release/app-release.aab`：Google Play 或其他支持 AAB 的发行渠道使用。

## GitHub Actions

`.github/workflows/android-widget.yml` 仅支持手动触发，同一 ref 上新的 run 会取消未完成的旧 run。它会在 Ubuntu runner 上安装 SDK 35，构建可直接安装的 debug APK、release APK、四种 ABI 分包以及 AAB，并将它们作为 workflow artifact 上传。构建不依赖 API Key，也不会把任何站点凭据写入仓库。Dependabot 每周只扫 `android-widget/` 的 Gradle 生态，不会打开生产发布变量。

未配置签名密钥时，debug APK 使用 Android 调试签名，可以直接安装；release APK/AAB 是未签名发行产物。正式分发和后续覆盖升级需要在仓库 Actions Secrets 中配置：

- `ANDROID_KEYSTORE_BASE64`：JKS/PKCS12 文件的 Base64 内容。
- `ANDROID_KEYSTORE_PASSWORD`：keystore 密码。
- `ANDROID_KEY_ALIAS`：签名 Key 的 alias。
- `ANDROID_KEY_PASSWORD`：签名 Key 密码。

配置后，Actions 会使用同一份 keystore 签署 release APK 和 AAB。不要把 keystore 或密码提交到仓库。
