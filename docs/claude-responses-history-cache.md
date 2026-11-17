# Claude Responses 历史缓存验证（2026-11-17）

## 改动范围

- 仅在 Anthropic OAuth（包括 Setup Token）账号的 `/v1/responses` 转换出口补充历史消息缓存断点。
- 独立设置 `enable_claude_responses_message_cache`，默认开启；后台名称为「Codex 调用 Claude 的历史缓存」。
- 使用 5 分钟 TTL，保留已有缓存断点及其 TTL，在剩余名额内优先缓存消息尾部，再补上一条 user 消息的历史边界。总数受现有 4 个断点限制。
- 跳过空文本、thinking、redacted_thinking 等不可直接标记的内容。文本、工具调用 ID、工具结果、thinking 签名及消息顺序保持不变。
- 复用现有会话绑定、协议转换、流式响应、用量解析及计费逻辑。原生 Messages、API Key、OpenAI 和 Grok 转发不调用此补充函数。
- 全局 `rewrite_message_cache_control` 保持原有语义与默认值，新功能不依赖开启全局改写。

## 本地验证

测试镜像 `sub2api:claude-history-cache-test` 在本地独立 Docker Compose 项目 `sub2api-claude-cache` 运行，使用独立 PostgreSQL、Redis 和模拟上游。

通过的检查：

- Docker 内运行 34 项后端测试（含 91 个子测试），覆盖多轮前缀一致性、长工具会话、流式/非流式转换、OAuth/Setup Token 与 API Key 的开关作用范围、已有 1h 标记、thinking 签名、断点上限、TTL 顺序和用量解析。
- `go test -tags=unit ./internal/pkg/apicompat ./internal/handler/admin ./internal/server -count=1 -timeout=5m`：相关包分别通过。
- `go vet -tags=unit ./internal/service ./internal/handler/admin ./internal/server ./internal/pkg/apicompat`：通过。
- 前端设置页 45 项测试、中英文 key 完整性 3 项测试：共 48 项通过。
- `vue-tsc -b`、Vite 生产构建，以及修改前端文件的 ESLint 检查：通过。
- 7 组 Docker 端到端检查通过：开/关各自的流式及非流式三轮对话、API Key 转换保持原行为、原生 Messages 保留客户端标记、设置持久化与部分更新保留显式关闭值。

模拟上游的 token 计数仅用于协议与前缀匹配检查，真实缓存效果以下述上游实测为准。

## 真实 Anthropic 上游实测

本地 Docker 内运行修改后的网关，使用账号 #46 的有效访问凭证和原有出口路径，向 `claude-opus-4-8` 发出 4 次合成数据请求。测试未复制 refresh token，未更新生产数据库，未部署或重启生产应用。每次输出上限为 32 token，实际输出均为 4 token。

使用相同长度的合成参考数据，关闭和开启开关各验证两轮。比较以本地网关持久化的独立 token 桶为准：Responses 响应的 `usage.input_tokens` 包含缓存部分，不能直接作为未缓存输入。

| 配置与轮次 | 普通输入 | 缓存写入 | 缓存读取 | 输出 | 网关折算费用 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 关闭，第 1 轮 | 14,455 | 26,559 | 0 | 4 | $0.23836875 |
| 关闭，第 2 轮 | 14,475 | 0 | 26,559 | 4 | $0.08575450 |
| 开启，第 1 轮 | 2 | 14,453 | 26,559 | 4 | $0.10372075 |
| 开启，第 2 轮 | 2 | 20 | 41,012 | 4 | $0.02074100 |

结果：开启后第二轮读取了上一轮新增的 14,453 个历史 token，仅为本轮新增部分写入 20 个缓存 token。普通输入从 14,475 降至 2，下降约 99.99%；第二轮折算费用下降约 75.81%。四次请求均返回 HTTP 200。

以上验证证明历史消息缓存已被真实上游接受并命中。折算费用依据当前网关价格配置；订阅额度节省比例仍应以 Anthropic 的实际用量窗口为准。首次建立缓存需要写入，长间隔、模型变更和历史前缀变化仍可能造成未命中。

测试完成后已清除本地临时访问凭证、代理凭据与 Redis 缓存，并关闭临时 SSH 通道。报告不包含请求正文、访问凭证或 API Key。

## 回退

关闭「Codex 调用 Claude 的历史缓存」即可停止补充断点。更新其他设置时未提交此字段，会保留当前值。无需修改数据库结构。
