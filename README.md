# lynn-ui

一个无损的订阅转换器：读入完整原始订阅链接，输出完整正确的 Clash（Mihomo）YAML。

## 它修什么

把节点从订阅链接转成 Clash YAML 的时候，市面上两个常用转换器各坏一半：

| | 3x-ui 面板 | sublink（旧版） |
|---|---|---|
| VLESS+REALITY | 全（public-key、short-id、support-x25519mlkem768 都有） | **丢 public-key**，REALITY 握不了手 |
| VLESS+XHTTP | 全（mode、path、x-padding-bytes 都有） | **丢 xhttp-opts** |
| HY2 | **丢 obfs / obfs-password**（外链节点），**没有 sni、skip-cert-verify**（所有 HY2） | 全（obfs、sni、skip-cert-verify 都有） |

原始订阅（base64 链接）本身是全的，丢东西的是转换那一步。lynn-ui 把完整原始链接解析成统一模型，再原样输出每一个字段，入站节点和外部链接节点走同一条路，不做区分，所以不管入站还是外部，拉出来的都是全的。

具体保留的字段：

- **VLESS REALITY**：public-key（pbk）、short-id（sid）、support-x25519mlkem768、flow、client-fingerprint（fp）、servername（sni）、network、tls、udp、uuid、encryption。
- **VLESS XHTTP**：alpn、mode、path、x-padding-bytes、host、servername、fingerprint、network=xhttp（`extra` JSON 里的 mode / xPaddingBytes 也会作为后备读取）。
- **HY2**：password、obfs、obfs-password、sni、skip-cert-verify、alpn、udp、ports、up/down、hop-interval。
- 另外保留：ws-opts、grpc-opts、tls、flow 等。

两个说明：

- HY2 链接本身没有 sni / insecure 时，默认用服务器名做 sni、skip-cert-verify 填 true（和已知能连的输出一致）。证书是有效的，Mihomo 也会默认用服务器名做 SNI。可用 `--hy2-sni-host=false` / `--hy2-skip-verify=false` 改。
- REALITY 的 `spx`（SpiderX）不输出：Mihomo 的 reality-opts 没有这个字段，面板自己输出的能连的 VLESS 里也没有它。

## 支持的协议

vless（reality / tls / xhttp / ws / grpc / tcp）、hysteria2、trojan、vmess、shadowsocks。

## 构建

```bash
go build -o lynn-ui ./cmd/lynn-ui
```

只需要 Go 1.24+，唯一依赖是 `gopkg.in/yaml.v3`。

## 用法

### 命令行

```bash
# 订阅 URL（面板的原始订阅）、本地文件、或 -（stdin）都行
lynn-ui convert https://example.com:2096/superpro/<subId>
lynn-ui convert ./subscription.txt
cat subscription.txt | lynn-ui convert -

# 写到文件
lynn-ui convert <订阅> --out clash.yaml

# 改 HY2 默认值（默认两个都是 true）
lynn-ui convert <订阅> --hy2-sni-host=false --hy2-skip-verify=false
```

输出是一份可直接用的 Clash 配置：`proxies`（全部节点，字段齐全）加一个最小的 `PROXY` select 组。

### 规则合并（v0.2.0）

默认输出只有节点（proxies + 最小 PROXY 组），Shadowrocket 这类只取节点的客户端够用；拿订阅当完整配置的 Mihomo / Clash 客户端会丢规则和 dns。加 `--rules` 就把规则文件合并进去：

```bash
# 用二进制里嵌的规则（和面板 subClashRules 指向的同一份文件）
lynn-ui convert <订阅> --rules embedded
lynn-ui serve --addr :8080 --rules embedded

# 或指定文件 / URL 覆盖嵌的版本
lynn-ui convert <订阅> --rules ./my-rules.yaml
```

合并后的输出：proxies + 20 个 proxy-groups（PROXY 在首位，后接规则文件的 19 个组）+ 45 个 rule-providers + 48 条 rules + dns。规则文件在启动时解析校验（组名不能叫 PROXY、规则目标组必须存在、RULE-SET 引用的提供方必须存在），校验不过直接报错退出，不会发出坏订阅。

嵌的规则来源：`converter/rules.yaml`，是 `clash-rules-comprehensive.yaml`（面板 subClashRules 指向的 GitHub 文件）的逐字副本，构建时嵌进二进制。改规则 = 更新这个副本、重新构建、重新部署。不加 `--rules` 时输出保持纯节点，可随时回退。

### HTTP 服务

```bash
lynn-ui serve --addr :8080
```

- `GET /clash?url=<订阅地址>`：拉取订阅并返回 Clash YAML。
- `POST /clash`：body 是订阅内容（base64 或明文链接），返回 Clash YAML。
- `GET /health`：`{"status":"ok"}`。

## 验证状态

- 单元测试（`go test ./...`）：25 个，全部通过，只用假数据（假 UUID、假密码、假公钥）。其中规则合并 10 个：基本合并、无规则输出不变、ConvertLinks 走规则路径、PROXY 重名拒绝、缺目标组拒绝、缺提供方拒绝、proxies 段拒绝、no-resolve 标志处理、嵌的真实规则文件（19 组 / 45 提供方 / 48 规则）与 9 节点合并；另有 1 个 CLI 参数重排测试（`--rules` 放订阅地址后面也生效）。
- 集成验证：用真实面板原始订阅（9 个节点：3 个 VLESS+REALITY、3 个 VLESS+XHTTP、3 个 HY2）实测，9/9 节点字段齐全，无警告；`--rules embedded` 输出含 20 个 proxy-groups、45 个 rule-providers、48 条 rules、dns。
- Mihomo 实测：输出拼成完整配置后，Mihomo v1.19.34 `mihomo -t` 校验通过（真实数据和假数据各一次；v0.2.0 含规则的完整输出也通过）。

## 注意

- 本项目只做转换，不改面板、不改 VPS、不碰任何线上配置。部署（替换面板订阅）需要另外确认。
- 不要把含真实 UUID / 密码的订阅文件、输出文件提交进仓库。测试和文档里只用假数据。
