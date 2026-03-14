# clawscanner（中文文档）

[English README](./README.md)

`clawscanner` 是一个基于 Go 的 OpenClaw 内网资产扫描工具，提供端口探测、OpenClaw 指纹识别、基础版本漏洞检查与敏感路径暴露检测，并输出 JSON 报告。

## 功能概览

- **目标输入支持**
  - 单个主机/IP：`192.168.1.10`
  - CIDR：`192.168.1.0/24`
  - URL 自动归一化：`https://10.0.0.8`（自动提取主机）
  - 多目标逗号分隔
- **端口扫描**
  - 默认端口：`18789,19001,443,80,8080,8443`
  - 自定义端口/范围：`--ports 80,443,8080` 或 `--ports 8000-8100`
  - 并发控制：`--threads`（默认 `100`）
  - 超时控制：`--timeout` 秒（默认 `30`）
- **OpenClaw 指纹识别（仅对开放端口）**
  - HTML/Body 特征（`openclaw/moltbot/clawdbot`）
  - Header 特征（`Server` / `X-Powered-By`）
  - 健康检查接口（`/api/v1/health`）
  - favicon mmh3 匹配（默认哈希 `-1172715710`）
  - 同一 `target + port` 聚合，命中越多置信度越高
- **漏洞/泄露检查（仅对开放端口）**
  - 版本比对规则检查
  - 敏感路径探测（如 `/.env`、`/.git/config`），含基础误报收敛
- **输出与报告**
  - 彩色终端过程日志与汇总表格
  - JSON 报告输出到文件（`-o`）或 stdout（不指定 `-o`）
  - finding 包含 `target`、可选 `port`、可选 `accessUrl`

## 快速开始

### 编译

```bash
go build -o clawscanner ./cmd/clawscanner
```

### 执行

```bash
./clawscanner 192.168.1.0/24 --ports 80,443,8080 -o results.json
```

### URL 目标示例

```bash
./clawscanner https://137.184.38.179 --ports 443 -o results.json
```

## CLI 用法

```bash
clawscanner <target|cidr> [--ports 18789,8080,3000] [--threads 100] [--timeout 30] [-o results.json]
```

### 常用参数

- `--ports`：自定义端口列表/范围
- `--threads`：扫描并发（默认 `100`）
- `--timeout`：TCP 超时秒数（默认 `30`）
- `-o`：JSON 报告输出路径
- `--quiet`：关闭过程日志和终端汇总表格
- `--requester`、`--scope`、`--time-window`、`--source`：授权元数据

## JSON 报告结构

顶层字段：

- `schemaVersion`
- `taskMeta`（任务ID、时间、状态、目标数、端口数）
- `summary`（`findingCount`）
- `findings[]`

finding 关键字段：

- `findingId`、`findingType`、`severity`、`ruleId`
- `target`、可选 `port`、可选 `accessUrl`
- `evidencePattern`、`evidenceMasked`
- `confidence`、`requiresManualReview`、`falsePositiveState`、`recommendation`

## 开发校验

```bash
./scripts/verify.sh
```

脚本会依次执行：

1. `gofmt -w ./cmd ./internal`
2. `go vet ./...`
3. `go test ./...`
4. `go build ./...`

## 目录结构

- `cmd/clawscanner/main.go`：CLI 入口与终端输出
- `internal/discovery/`：目标解析与端口/服务发现
- `internal/vulnscan/`：指纹识别、版本检查、路径泄露检查
- `internal/models/result.go`：报告数据结构
- `internal/output/json.go`：JSON 报告写出

## 说明

- 指纹与漏洞检测仅在端口扫描确认开放后执行。
- 为提升资产识别覆盖率，当前 HTTPS 探测采用宽松证书校验模式。
