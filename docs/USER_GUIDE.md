# OneCVE 使用手册

本文介绍 OneCVE 本地 Web 工具的部署、项目导入、扫描、复核和数据管理。推荐使用 Docker Compose，无需在宿主机单独安装 LLVM、Clang、SVF、Saber、Python 或 Node.js。

## 1. 启动与访问

在项目根目录执行：

```bash
docker compose up --build -d
docker compose ps
```

容器状态变为 `healthy` 后访问：

- Web 工作台：<http://127.0.0.1:3000>
- API 健康检查：<http://127.0.0.1:8000/api/health>

停止、重新启动和查看日志：

```bash
docker compose stop
docker compose start
docker compose logs -f onecve
```

## 2. 导入项目

在“项目”页面点击“导入项目”，可导入公开 Git 仓库或上传源码压缩包。Docker 容器默认不能读取宿主机任意目录；需要使用本地目录时，应先在 Compose 中添加明确的只读目录挂载。

导入后可在项目列表查看构建系统、源文件数量、扫描和结果数量及磁盘占用。删除项目会级联清理其任务、结果和数据，请在操作前确认。

## 3. 配置并开始扫描

点击项目右侧“扫描”，选择需要的检测类型：

- 内存泄漏（LEAK / CWE-401）
- 重复释放（DFREE / CWE-415）
- 释放后引用（UAF / CWE-416）
- 文件未关闭（FILE / CWE-775）
- 空指针解引用（NPD / CWE-476）

并行检测进程默认根据硬件配置给出建议值。每一路都会启动独立 Saber 子进程，内存有限时不要设置过高。扫描过程依次完成源码与构建识别、LLVM Bitcode 生成、内存语义建模、漏洞扫描和结果解析。

## 4. 查看与处理结果

“漏洞结果”页面支持按任务、漏洞类型、LLM 复核状态和人工验证状态筛选，并可导出 JSON 或 CSV。打开详情后可以查看源码位置、原始 Saber 报告、调用路径和 LLM 复核结果。

人工处理包括：

- 确认漏洞：标记为已验证。
- 标记误报：记录人工判断为误报。

可以勾选单条或多条结果后发起 LLM 复核，也可以删除所选结果。删除操作不可从页面恢复，必要时请先导出报告。

## 5. 配置 LLM 复核

在“本地设置”中填写兼容 OpenAI Chat Completions 的模型名称、Base URL、Chat 路径、API Key、超时和并发线程数，然后使用“测试 API 连接”验证配置。

本地模型运行在 Docker 宿主机时，Base URL 通常应使用：

```text
http://host.docker.internal:端口/v1
```

启用远程模型会发送漏洞报告、分析路径和相关源码切片。敏感项目应关闭 LLM 复核或使用本地模型服务。

## 6. 数据与清理

Docker 部署的数据保存在 `onecve-data` 卷中，包括导入源码、Bitcode、扫描报告、审核状态和本地设置。

```bash
docker volume inspect onecve-data
```

以下命令只删除容器，不删除数据卷：

```bash
docker compose down
```

以下命令会永久删除 OneCVE 数据卷，请谨慎执行：

```bash
docker compose down -v
```

项目页面的“清理产物”只清理可重新生成的构建产物，不删除项目源码和漏洞结果。

## 7. 常见问题

### Docker 构建时间较长

首次构建需要安装 LLVM 18 并编译定制 SVF/Saber。后续构建会复用 Docker 缓存；清理 BuildKit 缓存后，下一次构建会重新下载并编译。

### 项目编译失败

OneCVE 包含常见 C/C++ 构建工具和开发库，但无法覆盖所有项目依赖。根据任务诊断安装缺失依赖，或基于根目录 Dockerfile 创建扩展镜像。

### 页面无法访问

检查容器状态和端口占用：

```bash
docker compose ps
docker compose logs --tail=200 onecve
```

默认端口为 `127.0.0.1:3000` 和 `127.0.0.1:8000`，不会暴露到局域网。
