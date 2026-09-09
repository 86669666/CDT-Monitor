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

检查时间：2026-09-10 02:42 Asia/Taipei（`2026-09-09T18:42Z`）。这台 ops 工作区 **不能** 本地出包，不要把本机未构建写成 APK 已验证。`java` / `javac` 仍不存在，`JAVA_HOME` 为空。`./gradlew --version` 输出 `ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.`

| 依赖 | 本机状态 |
| --- | --- |
| JDK 17 / `java` / `javac` | 不存在，`JAVA_HOME` 为空 |
| Android SDK 35 / `sdkmanager` / `adb` | 不在 PATH |
| Gradle 8.10.2 | 不在 PATH；改用仓库 `./gradlew`（Wrapper 8.10.2，checksum 已钉死，`networkTimeout=120000`，`android.builder.sdkDownload=false`，`org.gradle.daemon=false`，`org.gradle.workers.max=2`，`org.gradle.parallel=false`，`org.gradle.caching=false`，`org.gradle.configuration-cache=false`，`org.gradle.vfs.watch=false`） |
| Gradle Wrapper | 已加入 `gradlew` / `gradle-wrapper.jar`；本机 `sha256sum gradle/wrapper/gradle-wrapper.jar` = `2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046`，与 `gradle/actions` wrapper-validation 中 Gradle **8.10.2** 条目一致。本机仍缺 JDK，所以 **没有** 跑过 assemble |

因此本机出包仍是 blocker（缺 JDK/SDK），不要把 Wrapper 入库写成 APK 已验证。YAML 里的支持路径是手动触发 `.github/workflows/android-widget.yml`，但该 workflow **尚未在本 fork 登记**：`gh workflow list --repo 86669666/CDT-Monitor` 只有 `CI` 和 `Publish Guard`；`gh workflow run android-widget.yml --ref work/ops` 返回 **HTTP 404**。不要为了登记小组件 workflow 去合仍带未加开关 `auto-release.yml` 的 `origin/main`。签名密钥只通过 Actions secrets 注入；当前 `gh secret list` 为空，keystore 不要进 git。

产物位于 `app/build/outputs/`（CI 成功后才有，本机没有）：

- `apk/debug/*.apk`：一份未做 ABI 分包的 debug APK（调试签名，可直接安装）。
- `apk/release/*.apk`：一份未做 ABI 分包的 release APK（未配置 keystore 时文件名会带 `-unsigned`）。
- `bundle/release/app-release.aab`：Google Play 或其他支持 AAB 的发行渠道使用。

## GitHub Actions

`.github/workflows/android-widget.yml` 仅支持手动触发，同一 ref 上新的 run 会取消未完成的旧 run。checkout 之后会用与 `setup-gradle` 同一 SHA 的 `gradle/actions/wrapper-validation` 核对 Wrapper jar，然后非交互接受 SDK 许可并安装 SDK 35（避免 `sdkmanager` 卡在许可证提示上耗尽 20 分钟），再用带 `gradle-home-cache-cleanup: true` 的 `setup-gradle` 构建一份 debug APK、一份 release APK 以及 AAB（不再打 ABI 分包），并将它们作为 workflow artifact 上传（保留 7 天）。构建不依赖 API Key，也不会把任何站点凭据写入仓库。Dependabot 每周只扫 `android-widget/` 的 Gradle 生态，不会打开生产发布变量。

截至 `2026-09-09T18:42Z`，该 workflow **没有** 出现在 fork 的 Actions 列表里，因此也 **没有** 跑过。这仍不是本机 APK，不是 Play 上架，更不是把 PR#2 合进未加开关 `main` 的理由。

未配置签名密钥时，debug APK 使用 Android 调试签名，可以直接安装；release APK/AAB 是未签名发行产物。正式分发和后续覆盖升级需要在仓库 Actions Secrets 中配置：

- `ANDROID_KEYSTORE_BASE64`：JKS/PKCS12 文件的 Base64 内容。
- `ANDROID_KEYSTORE_PASSWORD`：keystore 密码。
- `ANDROID_KEY_ALIAS`：签名 Key 的 alias。
- `ANDROID_KEY_PASSWORD`：签名 Key 密码。

配置后，Actions 会使用同一份 keystore 签署 release APK 和 AAB。解码后的 JKS 只写在 runner 的 `$RUNNER_TEMP`（`umask 077` / `chmod 600`），job 结束前（含失败）会 `shred`/`rm`，不会随 artifact 上传。不要把 keystore 或密码提交到仓库。
