# 电脑端泄漏检测工具

此目录拥有 Shell 生命周期入口和 Python HTTP/ADB/Shark 集成，本目录为独立仓库，以父仓库 MrcdOpt/leak-radar submodule 接入。Python 模块放 src/leak/radar，脚本只封装 Python 入口；采用标准库，Token、手机号及 HTTP 鉴权只读被忽略的 local.properties；.runtime 仅保存开关和运行状态，禁止保存、提交或打印凭据。非隐私运行配置可使用环境变量。Git 提交说明使用中文，不主动推送。

运行产物归本工具所有：.runtime 保存服务状态和日志，reports 保存每次采集原始证据。均不提交。停止服务不删除报告，报告由开发者手动清理。新功能需覆盖协议校验、进程生命周期或结果解析的真实边界。不要实现 Gradle Hook，除非用户另行要求。
