# roundtrip

`bitcoin-libp2p` 之上的业务消息壳：一条已认证 libp2p 连接之上的一来一回请求/响应，
同一份签名同时落到 WebSocket / WebRTC Direct 和 HTTP(S) 上。

**双语言对照项目**：TypeScript 与 Go 两侧都有对应实现，由同一套测试数据钉死。

## 文档

- [原始需求](docs/原始需求.md)
- [最简签名请求响应协议](docs/最简签名请求响应协议.md) —— 协议规范
- [施工单](docs/施工单.md) —— 实现边界、施工顺序与验收方式（含双语言范围约定）
- [消融测试结果](docs/消融测试结果.md) —— 逐项删除机制的实测结果，两种语言分别记录

上游 `bitcoin-libp2p` V1 明确不做业务消息壳（见其需求文档 §4），本项目补这一层。
身份模型、Noise、PeerId、uvarint 分帧与 WebRTC Direct 契约全部沿用上游，不重做。

## 消息壳

请求与响应都是 JSON + JCS（RFC 8785）规范编码，各自由发送者私钥签名。请求摘要就是请求 ID，
同时写进响应的 `reply_to`，所以关联关系由签名而不是传输层保证。

```text
unsigned   = 消息去掉顶层 sig 后的对象
bytes      = UTF8("roundtrip/v1\n") || JCS(unsigned)
sig        = Sign(private_key, SHA256(bytes))     // 一次哈希，严格 DER，low-S
request_id = base64url(SHA256(bytes))             // 仅请求
```

没有独立 `id`、`type`、`version` 字段，不做算法协商，不做身份握手。

协议文档 §6.2 的"受信 HTTPS 精简响应"只做消息层：解析、打包、签名与验签走同一套 API
（TS `parseTrimmedResponse` / `verifyTrimmedResponse`，Go `ParseTrimmedResponse` / `VerifyTrimmedResponse`），
签名使用独立前缀 `roundtrip/http-response/v1\n`，基础接收器继续拒绝该形态。
两种语言都没有传输适配实现它，也就没有生产开关。

## 代码

```text
testdata/vectors.json           两种语言共享的固定向量（唯一的测试数据契约）

typescript/src/core.ts          处理流程：call / send / handle / verifyResponse
typescript/src/envelope.ts      消息结构、JCS、摘要、严格读取（含精简响应形态）
typescript/src/signer.ts        签名者接口与本地实现
typescript/src/replay.ts        去重存储接口与内存实现
typescript/src/libp2p/          libp2p stream 适配，一次调用一个 stream
typescript/src/http/            HTTP 适配，POST /roundtrip
typescript/test/                阶段 1–6 的测试与消融实验
typescript/examples/            最小示例（http.ts、libp2p.ts）

go/core/                        同上四个职责，处理流程在 core.go
go/libp2p/                      libp2p stream 适配
go/http/                        HTTP 适配
go/core/*_test.go               阶段 1–6 的测试、消融实验与两个 Example
```

## 安装

```bash
npm install key-roundtrip                              # TypeScript，npm 上名为 key-roundtrip
go get github.com/bsv8/roundtrip/go/core              # Go，模块路径 github.com/bsv8/roundtrip/go
```

Go 模块的 `go.mod` 在仓库子目录 `go/` 下，因此 Go 侧的版本标签是 `go/v0.1.0` 而不是 `v0.1.0`；
`v0.1.0` 只作仓库级发布标记。锁定版本时用 `go get github.com/bsv8/roundtrip/go/core@go/v0.1.0`。

## 运行

```bash
cd typescript
npm install
npm run typecheck
npm test                    # 152 个测试，含真实 WebSocket 与 WebRTC Direct 承载
npm run example:http        # 最小 HTTP 示例
npm run example:libp2p      # 同一份壳在 WebSocket 与 WebRTC Direct 上各跑一次
npm run vectors             # 重新生成 testdata/vectors.json

cd ../go
go vet ./...
go test ./...               # 3 个包，含真实 WebSocket 与 WebRTC Direct 承载
```

## 边界

协议核心不知道 PeerId、SDP 和地址发现，传输适配不碰签名字段，业务授权在 handler 里做。
宿主与传输由上游 SDK 装配：TypeScript 用 `createHost`，Go 用 `golibp2p.NewHost`。
Go 的 WebRTC Direct transport 由应用显式装配，因为 go-libp2p 会读取 `PrivKey.Raw()`，
而上游 identity adapter 按设计不可提取——这是上游需求文档交给业务的一步。

默认的去重存储是单进程内存实现，跨重启和跨实例的防重放由应用提供持久共享存储，
库用 `capabilities` 明确标出它能保证什么、不能保证什么。
