# OneCVE

OneCVE 是一个面向 C/C++ 项目的本地 Web 漏洞检测工具。它将目标源码自动编译为 LLVM Bitcode，调用定制的 SVF 执行静态分析，并在网页中展示漏洞位置、源码证据、分析日志与复核结果。

## 主要功能

- 支持上传源码包、导入公开 Git 仓库。
- 自动识别并依次回退 `compile_commands.json`、CMake、Meson、Autotools 和 Make。
- 通用生成 LLVM Bitcode，支持编译数据库规范化、Bitcode 包装器和最低覆盖率检查。
- 支持五类漏洞检测：
  - 内存泄漏
  - 重复释放
  - 释放后引用
  - 文件未关闭
  - 空指针解引用
- 支持漏洞去重、源码切片、条件路径和 LLM 复核。
- 支持手动填写或从文件导入项目自定义的内存分配/释放函数。
- 支持源码在线查看、调用路径高亮与扫描统计。
- 支持人工确认漏洞或标记误报，并按 LLM 复核与人工验证状态筛选。
- 支持项目级联删除、扫描任务批量终止/删除和可重建产物清理。
- 展示 OneCVE 数据、构建产物和所在磁盘的空间占用。
- 支持导出 JSON 和 CSV 漏洞报告。

## Docker 环境

项目根目录的 Docker 配置会构建一个完整的本地运行镜像，其中包含：

- Ubuntu 24.04
- LLVM/Clang 18
- 定制的 SVF/Saber 与 `extapi.bc`
- CMake、Ninja、Make、Bear、Meson、Autotools 和 Git
- Python、FastAPI 与 OneCVE 分析代码
- Node.js 22 与生产版 Web 前端

目标开源项目自身需要的特殊开发库无法统一预装。如果某个项目依赖额外库，可在本镜像基础上扩展安装。

## Docker 快速部署

需要预先安装 Docker Desktop，或 Docker Engine 与 Docker Compose v2。首次构建需要下载系统依赖并编译 SVF，建议至少准备 8 GB 内存和 20 GB 可用磁盘。

### 1. 配置可选的 LLM

不使用 LLM 时可跳过此步骤。

Linux/macOS：

```bash
cp .env.example .env
```

Windows PowerShell：

```powershell
Copy-Item .env.example .env
```

然后编辑 `.env`：

```dotenv
OPENAI_API_KEY=your-api-key
NSPA_LLM_MODEL=gpt-4o-mini
NSPA_LLM_BASE_URL=https://api.openai.com/v1
NSPA_LLM_CHAT_PATH=/chat/completions
```

也可以在“本地设置”中保存 LLM 配置。API Key 仅保存在本机 OneCVE 数据目录中，接口不会回传明文。

### 2. 构建并启动

```bash
docker compose up --build -d
```

查看启动状态：

```bash
docker compose ps
docker compose logs -f onecve
```

首次构建完成后访问：

- Web 工作台：<http://localhost:3000>
- API 健康检查：<http://127.0.0.1:8000/api/health>
- API 文档：<http://127.0.0.1:8000/docs>

Compose 只将端口绑定到 `127.0.0.1`，不会默认暴露到局域网。

### 3. 停止或重新启动

```bash
docker compose stop
docker compose start
```

完全停止并删除容器：

```bash
docker compose down
```

扫描数据保存在名为 `onecve-data` 的 Docker 卷中，执行 `docker compose down` 不会删除数据。

### 4. 更新镜像

源码更新后重新构建：

```bash
docker compose build
docker compose up -d
```

## 使用说明

完整的项目导入、扫描配置、漏洞审核、报告导出、数据管理和故障排查说明见：

[OneCVE 使用手册](docs/USER_GUIDE.md)

## 数据与安全

- 默认数据卷：`onecve-data`
- 容器内数据目录：`/data`
- Web 端口：`127.0.0.1:3000`
- API 端口：`127.0.0.1:8000`
- 容器以非 root 用户执行扫描任务。
- 容器直接以非 root 用户运行；Compose 删除全部 Linux capabilities，并启用 `no-new-privileges`。
- 上传源码包会检查目录穿越、绝对路径、链接和设备文件。
启用远程 LLM 复核后，漏洞报告、调用路径和相关源码切片会发送给所配置的模型服务。敏感项目请关闭漏洞 LLM 复核或使用本地模型服务。

## License

项目许可证见 [LICENSE](LICENSE)。SVF 及镜像内其他第三方组件分别遵循其自身许可证。
