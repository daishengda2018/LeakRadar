# Leak Radar

本工具属于 MrcdOpt 的电脑端采集分析层，源码集中于此目录，通过 Git Submodule 接入父仓库。提供手动启动、HTTP 事件、ADB 采集、Shark 2.14 分析及可选钉钉通知；当前不接 Gradle Hook，不修改 Android 模块。

## 准备与启动

使用 uv 和 Python 3.12.15，运行时采用 Python 标准库，锁文件固定构建依赖。提前安装 ADB、Java 和 **Shark CLI 2.14**，将可执行文件加入 PATH。Shark 版本不一致时明确拒绝运行，不自动升级或安装。

```bash
cd MrcdOpt/leak-radar
./scripts/setup.sh

export LEAK_PACKAGE=com.fun.share
# 多设备时必须明确指定；单设备可以省略。
export DEVICE_SERIAL=<adb设备序列号>
./scripts/start.sh
./scripts/stop.sh
```

`setup.sh` 执行 `uv sync --locked` 并检查工具。未安装 Shark CLI 时执行：

```bash
brew install leakcanary-shark
```

安装后执行 `shark-cli --version` 检查版本；当前工具要求 2.14。若 Homebrew 提供的版本不同，可从 [Release v2.14](https://github.com/square/leakcanary/releases/tag/v2.14) 获取对应安装包。环境检查通过不代表实际 Heap 分析兼容性已经验证。

`start.sh` 使用文件锁串行化启动，通过 `/health` 的项目路径、实例标识和 PID 验证服务身份。重复启动复用同一实例，尝试配置所选设备的 ADB Reverse。配置包名或端口变化时要求先停止；其他配置变更也应先停止再启动。不同服务占用端口时启动失败。

`stop.sh` 只给匹配身份的服务发送信号，并终止其正在执行的采集分析命令。不删除报告，不删除 ADB Reverse 映射。无法核实身份时拒绝杀进程，检查 `.runtime/service.json` 与日志后人工处理。异常退出的子进程及设备临时 HPROF 可能需要手动核实清理。

## 配置

| 环境变量 | 默认 | 用途 |
| --- | --- | --- |
| `LEAK_PACKAGE` | 必填 | 允许触发采集的 App 包名，V1 仅主进程 |
| `DEVICE_SERIAL` | 单设备自动选择 | 运行期间固定设备 |
| `LEAK_HOST` | `127.0.0.1` | 局域网模式可设为 `0.0.0.0` |
| `LEAK_PORT` | `8765` | HTTP 及 ADB Reverse 端口 |
| `LEAK_TOKEN` | 无 | 请求 Bearer 令牌，非回环监听必须配置 |
| `LEAK_COOLDOWN_SECONDS` | `60` | 同 PID 分析成功后的采集冷却 |
| `LEAK_DINGTALK_TOKEN` | 无，通知关闭 | 可选钉钉机器人 token；服务启动时从环境继承 |

密钥通过环境传入，不提交或打印。当前不自动读取 `.env`，也不自动将地址写入 Gradle。局域网 IP 和 Android 明文网络配置由后续宿主集成处理；App 需要实际请求 `/health` 验证连通性。

## HTTP 协议

`GET /health` 返回服务标识、协议版本、实例、PID、根目录、目标包名和设备序列号，供启动校验和 Android 连通检查。

`POST /leak-event` 在配置令牌时要求 `Authorization: Bearer <token>`，请求体上限 64 KiB：

```json
{
  "packageName": "com.fun.share",
  "pid": 12345,
  "timestamp": 1792700000000,
  "retainedCount": 1,
  "reason": "ActivityDestroyed",
  "candidates": [
    {"key": "观察key", "className": "com.example.MainActivity", "description": "onDestroy"}
  ]
}
```

示例 timestamp 为墙上时间毫秒，发送时替换成当前值；与电脑相差超过 5 分钟拒绝接收。PID 与 retainedCount 必须为正整数，包名必须匹配配置，reason 最长 1024 字符。candidates 当前只归档，不作为分析结论。Android 的 ConfirmedObject 需要由后续 HTTP 集成补充包名、PID、时间等字段。

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

## 输出与通知

- `.runtime/`：生命周期锁、服务身份、追加日志和成功通知签名。工具拥有这些运行状态，停止后保留；确认服务已停止再手动清理。
- `reports/<jobId>/`：event.json、capture.log、HPROF、analysis.log、result.json。由工具生成，仅本机保留，需由开发者手动清理；不发送原始 HPROF。
- `.venv/`：uv 管理，可用 uv sync 重建。

这些目录均忽略提交。分析确认有泄漏且配置钉钉 token 时才通知，按“包名＋Shark signature”在本机去重，成功发送后写记录；失败记为 notification=failed，不改变分析结果。当前无自动通知重试；需要重新分析或后续增加独立重试入口。机器人需支持 access-token 模式，尚未实现加签、@手机号和引用链摘要。钉钉不会自动打开或提交真实测试消息。

## 验证与待完成项

```bash
uv run --locked python -m unittest discover -s tests -v
bash -n scripts/setup.sh scripts/start.sh scripts/stop.sh
```

测试使用合成输出与隔离的假 ADB/Shark，验证结果解析、失败分类、事件校验、PID 重启检查、合并/冷却、真实 HTTP 鉴权及后台进程重复启动/停止。不能据此认定真实 Heap 标记兼容。

后续必须验证已知泄漏的采集与结果、SimpleLeakCanary 标记识别、真实手机连通、真实持续事件下的合并效果和通知策略。Gradle Hook、Android HTTP 监听器、子进程和多设备调度未实现。

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
