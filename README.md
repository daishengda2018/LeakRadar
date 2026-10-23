# LeakRadar

本工具属于 MrcdOpt 的电脑端采集分析层，源码集中于此目录，通过 Git Submodule 接入父仓库。提供手动启动、HTTP 事件、ADB 采集、Shark 2.14 分析及可选钉钉通知；提供可复用的 Gradle Debug 启动 Hook；Android HTTP 事件发送仍需宿主接入。

## 使用与接入

LeakRadar 在电脑端接收 App 的疑似泄漏事件，使用 ADB 抓取目标进程的堆，再由 Shark 分析引用链。完整接入包含电脑端服务和 Android 端事件发送两部分；Gradle Hook 负责启动服务。

### 1. 获取工具并准备环境

已接入本工具的 MrcdOpt 项目，在父仓库执行：

```bash
git submodule update --init --recursive
cd MrcdOpt/leak-radar
```

其他 Android 项目可在 Gradle 根目录添加 submodule：

```bash
git submodule add https://github.com/daishengda2018/LeakRadar.git leak-radar
cd leak-radar
```

提前安装 uv、ADB、Java 和 **Shark CLI 2.14**，将可执行文件加入 PATH。工具使用 Python 3.12.15，运行时采用标准库，构建依赖由锁文件固定。未安装 Shark CLI 时执行：

```bash
brew install leakcanary-shark
```

用 `shark-cli --version` 确认版本为 2.14；工具拒绝其他版本，不自动安装或升级。随后执行：

```bash
./scripts/setup.sh
```

该脚本执行 `uv sync --locked` 并检查工具。若本机安装来源提供其他 Shark 版本，需自行准备 2.14 对应的 CLI。

### 2. 配置本地参数并关闭测试通知

在 Android 项目的 Gradle 根目录 `local.properties` 中添加以下配置，保留原有的 `sdk.dir` 等内容：

```properties
simpleLeakCanary.dingTalkToken=<机器人Token>
simpleLeakCanary.atMobiles=<手机号，多个用逗号分隔>
```

**应用 Hook 后，Debug 构建必须提供这两项非空配置**，即使关闭钉钉发送或设置 `leakRadar.enabled=false` 也会校验；Release 不校验。隐私配置只读此文件，不写入源码或运行状态。宿主仓库需要确保 `local.properties` 被 Git 忽略。

首次验证先在工具目录关闭钉钉发送，只输出报告日志：

```bash
./scripts/dingtalk.sh off
```

本地关闭开关不会随仓库分发。未设置开关时默认允许发送：配置有效 Token 后，分析发现新泄漏可能向钉钉发送真实消息。需要发送时再执行 `./scripts/dingtalk.sh on`。

### 3. 接入 Gradle Debug 启动 Hook

在 Android application 模块的 `build.gradle` 中应用：

```groovy
apply from: rootProject.file('leak-radar/scripts/gradle-hook.gradle')
```

连接并授权 Android 设备，使用 `adb devices` 确认设备在线。多设备时，在运行构建的环境中指定 `DEVICE_SERIAL`。返回 Gradle 根目录执行：

```bash
./gradlew :app:assembleDebug
```

将 `:app` 替换为实际 application 模块。Hook 自动读取 Debug variant 的 applicationId，并启动电脑端服务、配置 ADB Reverse。默认地址为设备端 `http://127.0.0.1:8765`。服务启动失败默认只警告；需要构建失败时使用 `-PleakRadar.strict=true`。

### 4. 接入 Android 端事件发送

MrcdOpt Demo 已接入。其他宿主需要接入 SimpleLeakCanary，并参考父项目的以下文件：这些路径属于 MrcdOpt，独立克隆本工具不会包含它们。

| 参考文件（相对 MrcdOpt） | 用途 |
| --- | --- |
| `app/src/debug/java/com/mrcd/opt/libs/LeakRadarSetup.java` | 注册 `addOnObjectConfirmedListener`，在后台线程将二次确认事件 POST 到 `/leak-event` |
| `app/src/main/java/com/mrcd/opt/libs/DemoApp.java` | Application 初始化时调用 `LeakRadarSetup.install(this)` |
| `app/src/debug/AndroidManifest.xml` | Debug 网络配置入口 |
| `app/src/debug/res/xml/leak_radar_network_security.xml` | 允许 Debug 回环 HTTP 通信 |
| `app/src/release/java/com/mrcd/opt/libs/LeakRadarSetup.java` | Release 空实现，配合共用的 Application 调用 |

宿主还需声明 `android.permission.INTERNET`。发送内容包含包名、当前 PID、当前时间和候选对象元数据，具体字段见“HTTP 协议”。候选事件只触发采集，最终泄漏结论由电脑端 Shark 给出。

Demo 将首次观察等待设为 5 秒以加快测试；这不是二次确认间隔。移植时按宿主需要设置。若修改服务端口，也要同步修改 Android 请求地址。

当前 Demo 不发送 HTTP Bearer 请求头。若配置 `leakRadar.httpToken`，必须同步在宿主请求中添加 `Authorization: Bearer <token>`，否则服务返回 401。默认回环接入可不配置该项。

### 5. 验证接入并查看结果

安装并启动 Debug App，制造泄漏并退出相关页面。App 二次确认后应出现 `desktop_event_response` 日志，HTTP 202 表示事件已接收，随后电脑端进行抓堆和分析。在工具目录查看：

```bash
curl http://127.0.0.1:8765/health
tail -f .runtime/server.log
```

查看 `reports/<jobId>/result.json` 中的结果状态、`analysis.log` 中的引用链。有泄漏且关闭发送时，会输出 `notification_report` 并保存 `notification.txt`，通知状态为 `log_only`。HTTP 202 不代表已经分析出泄漏。

### 手动启动与停止

不通过 Gradle 启动时，在工具目录执行：

```bash
export LEAK_PACKAGE=com.example.app
# 多设备时必须指定；单设备可省略。
export DEVICE_SERIAL=<adb设备序列号>
./scripts/start.sh
# 使用结束后停止服务。
./scripts/stop.sh
```

`start.sh` 使用文件锁串行化启动，通过 `/health` 的项目路径、实例标识和 PID 验证服务身份。重复启动复用同一实例，并尝试配置所选设备的 ADB Reverse。更改启动配置后先停止再启动；不同服务占用端口时启动失败。

`stop.sh` 只停止身份匹配的服务及其采集分析命令，保留报告和 ADB Reverse 映射。无法核实身份时拒绝杀进程，可检查 `.runtime/service.json` 与日志。异常退出的子进程及设备临时 HPROF 可能需要手动核实清理。

## Gradle Debug 启动 Hook

在 Android application 模块应用脚本，MrcdOpt 的 app/build.gradle 已接入：

```groovy
apply from: rootProject.file('leak-radar/scripts/gradle-hook.gradle')
```

脚本为每个 Debug variant 注册 `ensureLeakDetector<Variant>`，挂接 `pre<Variant>Build`。当前无 flavor 的 App 可手动执行：

```bash
./gradlew :app:ensureLeakDetector
./gradlew :app:assembleDebug
```

目标包名来自该 variant 的最终 applicationId，无须另设 LEAK_PACKAGE；DEVICE_SERIAL 等非隐私运行配置通过环境传入；凭据只从宿主 local.properties 读取。外部脚本只在任务执行阶段启动，Sync/help 不启动服务，Release 任务不依赖启动任务。不要在 Release 构建中显式请求 Debug 的 ensure 任务。

| Gradle 属性 | 默认 | 说明 |
| --- | --- | --- |
| `leakRadar.enabled` | `true` | false 时只跳过服务启动 |
| `leakRadar.strict` | `false` | 启动失败默认警告并继续；true 时任务失败 |
| `leakRadar.directory` | `leak-radar` | 工具目录，相对 Gradle 根目录；支持绝对路径 |
| `leakRadar.localProperties` | `local.properties` | 隐私配置路径，相对 Gradle 根目录；支持绝对路径。两项必填配置的校验不受 enabled 和 strict 控制 |

```bash
./gradlew :app:assembleDebug -PleakRadar.enabled=false
./gradlew :app:ensureLeakDetector -PleakRadar.strict=true
```

多 flavor 项目使用明确的 `:app:ensureLeakDetectorYoyoDebug` 等任务；不使用仅用于无 flavor debug 的 `ensureLeakDetector` 别名。其他宿主先按实际工具路径应用脚本，再通过 leakRadar.directory 配置其运行目录。

Android Studio 正常 Debug 部署构建经过预构建任务时会触发。为了覆盖 IDE 跳过编译的情况，可在专用 Debug Run Configuration 的 Before launch 添加 Run Gradle task：`:app:ensureLeakDetector`（flavor 项目使用具体任务），保留原 Gradle-aware Make。不要将该步骤加到 Release 运行配置。当前未修改用户的 IDE 配置，IDE 点击 Run 的实际行为尚未人工验证。

实现使用执行阶段的 ExecOperations，已验证配置缓存存储及复用；每次执行仍检查服务，不把本地服务状态当编译输出缓存。`gradle-start.sh` 补充 Finder 启动 IDE 时可能缺少的 Homebrew uv 与 Android SDK PATH。服务启动失败不会自动安装软件或修改宿主网络配置。

## 配置

| 环境变量 | 默认 | 用途 |
| --- | --- | --- |
| `LEAK_PACKAGE` | 必填 | 允许触发采集的 App 包名，V1 仅主进程 |
| `DEVICE_SERIAL` | 单设备自动选择 | 运行期间固定设备 |
| `LEAK_HOST` | `127.0.0.1` | 局域网模式可设为 `0.0.0.0` |
| `LEAK_PORT` | `8765` | HTTP 及 ADB Reverse 端口 |
| `LEAK_COOLDOWN_SECONDS` | `60` | 同 PID 分析成功后的采集冷却 |

隐私信息只从 local.properties 读取，不使用环境变量或运行状态保存凭据。当前不自动读取 `.env`，也不自动将地址写入 Gradle。局域网 IP 和 Android 明文网络配置由后续宿主集成处理；App 需要实际请求 `/health` 验证连通性。

## HTTP 协议

`GET /health` 返回服务标识、协议版本、实例、PID、根目录、目标包名和设备序列号，供启动校验和 Android 连通检查。

`POST /leak-event` 在配置令牌时要求 `Authorization: Bearer <token>`，请求体上限 64 KiB：

```json
{
  "packageName": "com.fun.share",
  "appName": "YoYo",
  "versionName": "1.0",
  "versionCode": 1,
  "pid": 12345,
  "timestamp": 1792700000000,
  "retainedCount": 1,
  "reason": "ActivityDestroyed",
  "candidates": [
    {"key": "观察key", "className": "com.example.MainActivity", "description": "onDestroy"}
  ]
}
```

示例 timestamp 为墙上时间毫秒，发送时替换成当前值；与电脑相差超过 5 分钟拒绝接收。PID 与 retainedCount 必须为正整数，包名必须匹配配置，reason 最长 1024 字符。candidates 当前只归档，不作为分析结论。MrcdOpt Demo Debug 的 LeakRadarSetup 已在转发时补充包名、PID、会话及事件时间；其他宿主需接入自己的监听器。

响应 202：`accepted` 附带 jobId；同 PID 已排队或分析中返回 `merged`；成功分析冷却期间接收任务，工作线程等待冷却结束再采集。非法事件返回 400，鉴权失败 401，队列满返回 429。

同 PID 的重复事件保留最新事件作为一次后续采集，多次触发合并为一次；当前分析成功后等待冷却结束再补采。合并只控制采集触发，不保证归档每次事件或所有候选描述。全局最多 16 个活跃进程任务，V1 使用同一工作线程，冷却等待也占用该线程。队列仅在内存中，服务退出不会自动恢复任务。

## 采集与分析

服务单工作线程串行执行，下列命令在每次任务独立报告目录中运行：

```bash
shark-cli --device <serial> --process <package> dump-process
shark-cli --hprof <采集文件绝对路径> analyze
```

先校验事件 PID，再采集；采集后再次核验 PID，变化则记作采集失败。Shark 自己会重新按进程名解析 PID，这里不承诺消除所有进程重启竞争，也不支持子进程。Dump 必须由目标环境允许；缺少可调试权限等情况记录采集失败。

采集超时 120 秒，分析超时 600 秒，超时终止对应进程组。解析器固定依据 2.14 的 `HeapAnalysisSuccess.toString()` 契约，要求成功标记、三个数量段、分析耗时及数量匹配的签名；未知或不完整文本记作分析失败。不能用退出码为 0 或 retainedCount 判断是否泄漏。

结果状态为 `capture_failed`、`analysis_failed`、`no_leaks_found`、`leaks_found`。后两种只描述该次 Shark 的结果，不证明历史候选从未滞留或绝对不存在其他泄漏。

## 隐私配置只读 local.properties

默认自动读取工具父目录的 `local.properties`（当前为 MrcdOpt/local.properties），每次处理报告重新读取，不复制凭据到 .runtime。独立使用或其他目录布局时设置非隐私路径变量 `LEAK_LOCAL_PROPERTIES=/绝对路径/local.properties`。

```properties
simpleLeakCanary.dingTalkToken=<机器人Token>
simpleLeakCanary.atMobiles=<手机号，多个用逗号分隔>
# 仅局域网鉴权需要
leakRadar.httpToken=<HTTP共享令牌>
```

Debug 构建前强制校验 dingTalkToken、atMobiles 两项：缺失或为空立即失败，即使发送开关关闭或服务启动设为宽松模式也一样。Release 不校验。可用 Gradle 属性 `leakRadar.localProperties` 指定配置路径，Hook 会把同一路径传给服务。首次自动发现默认路径即可，无须导入；以下命令只校验、不保存凭据：

```bash
./scripts/configure-dingtalk.sh
```

手工命令的 --properties 参数仅用于本次校验；要让服务使用非默认路径，请使用 LEAK_LOCAL_PROPERTIES。读取支持本例的单行 key=value 格式，不解析续行或 Unicode 转义。手机号可用逗号分隔。

local.properties 已被 Git 忽略，源码和示例只允许占位符或明确的测试值。.runtime/notification.json 仅保存 dingTalkEnabled 开关；不再读取旧的环境 Token 或运行状态凭据。/health 的 notificationEnabled 只表示配置与开关允许发送，不证明接口投递成功。

## 输出与通知

- `.runtime/`：生命周期锁、服务身份、追加日志和成功通知签名。工具拥有这些运行状态，停止后保留；确认服务已停止再手动清理。
- `reports/<jobId>/`：event.json、capture.log、HPROF、analysis.log、result.json。由工具生成，仅本机保留，需由开发者手动清理；不发送原始 HPROF。
- `.venv/`：uv 管理，可用 uv sync 重建。

这些目录均忽略提交。分析确认有泄漏且配置钉钉 token 时才通知，按“包名＋Shark signature”在本机去重，成功发送后写记录；失败记为 notification=failed，不改变分析结果。当前无自动通知重试；需要重新分析或后续增加独立重试入口。机器人需支持 access-token 模式，尚未实现机器人加签。存在新签名时才发送通知；发送正文展示本次分析的全部 GC Root 引用链，与本次泄漏总数对应，引用链正文最多约 10 KB，超长时明确标记截断，完整内容保留在 analysis.log。这里的引用链描述对象持有关系，不是线程调用栈。发送开关默认开启，启用且配置有效 Token 时会发送真实消息；首次测试建议执行 `./scripts/dingtalk.sh off`。

## 验证与待完成项

```bash
uv run --locked python -m unittest discover -s tests -v
bash -n scripts/setup.sh scripts/start.sh scripts/stop.sh
```

测试使用合成输出与隔离的假 ADB/Shark，验证结果解析、失败分类、事件校验、PID 重启检查、合并/冷却、真实 HTTP 鉴权及后台进程重复启动/停止。不能据此认定真实 Heap 标记兼容。

后续必须验证已知泄漏的采集与结果、SimpleLeakCanary 标记识别、真实手机连通、真实持续事件下的合并效果和通知策略。Demo Debug 已实现回环 HTTP 监听器；其他宿主集成、子进程和多设备调度尚未实现。

依据：[Shark 2.14 CLI](https://github.com/square/leakcanary/tree/v2.14/shark-cli/src/main/java/shark)、[HeapAnalysis 文本契约](https://github.com/square/leakcanary/blob/v2.14/shark/src/main/java/shark/HeapAnalysis.kt)。父仓库架构文档位于 `MrcdOpt/simpleleakcanary/docs/架构设计.md`。

## 仓库与本地开发

独立仓库：[daishengda2018/LeakRadar](https://github.com/daishengda2018/LeakRadar) 。父仓库通过 `MrcdOpt/leak-radar` submodule 固定工具版本。源码、脚本和测试由本仓库维护，运行证据仍遵循上文清理规则。

```bash
# 在父仓库首次拉取工具
git submodule update --init --recursive

# 在工具目录修改、测试并提交
cd MrcdOpt/leak-radar
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
git add <本次修改的文件>
git commit -m "描述本次修改目的"
git push origin main

# 回到父仓库记录工具的新版本
cd ../..
git add MrcdOpt/leak-radar
git commit -m "更新泄漏分析工具版本"
```

执行 submodule update 后可能处于 detached HEAD，修改前先切换到 `main` 或新建工作分支。移动目录后先执行 uv sync，更新本地虚拟环境中的可编辑安装路径。


## 报告正文与 App 版本

Demo Debug 事件携带 appName、versionName 和 versionCode，分别来自应用标签及当前 APK 的 BuildConfig。通知标题形如 `【注意】MrcdOpt *v1.0* 检测到内存泄漏`；正文仅保留应用及版本、泄漏数量、本机报告路径和按 1、2、3 编号的 Signature 引用链；包名、PID、versionCode 可在 event.json 中查看。版本、数量、报告目录名及 Signature 使用星号标记。兼容旧事件：未提供名称则显示包名，未提供版本则省略版本，不猜测。

发送前以 INFO 输出 `[LeakRadar] notification_report` 和完整发送正文，包含 App 版本及引用链，不包含 Token 或认证 URL；同一正文保存在 reports/<jobId>/notification.txt。发送成功后输出 notification_sent，失败仍保留准备发送的正文并在 result.json 记录通知失败。发送开启时，全部签名均已通知过的任务不生成新的 notification.txt；关闭发送或缺少 Token 时仍为每次泄漏报告记录正文。日志查看：

```bash
tail -f .runtime/server.log
```

通知正文可能包含 @手机号及业务类名，随日志保留本机；仍不上传 HPROF。引用链超长时的截断规则保持不变，完整 Shark 输出在 analysis.log。


## 临时关闭钉钉发送，只输出日志

```bash
./scripts/dingtalk.sh off
# 恢复发送
./scripts/dingtalk.sh on
```

开关写入本地忽略配置，服务下一次处理报告时读取，无须重新构建 App。升级至支持此开关的代码后需要重启服务一次。关闭后仍分析 Heap，每次有泄漏的报告均输出 notification_report 并保存 notification.txt，result.json 的 notification 为 log_only，不调用钉钉接口，也不更新成功发送去重记录。修改 local.properties 不改变已有开关，重新开启也不会自动补发历史报告。健康接口 notificationEnabled 返回实际发送是否启用。
