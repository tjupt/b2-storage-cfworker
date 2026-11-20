# files.tju.pt Worker

Cloudflare Worker，为 `files.tju.pt` 提供新私有桶（`TJUPT-Attachments-v2`）的文件访问。

## 部署步骤

```bash
cd v2
npm ci
wrangler login
```

### 1. KV 命名空间（已建好时跳过）

`wrangler.jsonc` 里已经绑定了命名空间 `tjupt-files-policy`（id `012ef3f688ab4f3794c05358c860a775`），绑定名 `FILE_POLICY`。要新建一个的话：

```bash
wrangler kv namespace create tjupt-files-policy
```

把输出的 `id` 填进 `wrangler.jsonc` 的 `kv_namespaces[0].id`。

### 2. 写入三个 Secret

```bash
wrangler secret put B2_KEY_ID       # 新桶只读密钥 ID
wrangler secret put B2_APP_KEY      # 新桶只读密钥 Application Key
wrangler secret put SALT            # 附件签名密钥，等于站点设置 ATTACHMENT 段的 b2v2_sign_key（不是 $SECRET_SALT）
```

### 3. 部署

`files.tju.pt` 已经在控制台绑在这个 Worker 上。只有单个 Worker 权限的成员改不了自定义域名，`wrangler deploy` 会在同步域名那一步报 "No access to the specified resource"（代码其实已经上传）。所以用版本命令部署，不碰域名：

```bash
wrangler versions upload
wrangler versions deploy --yes   # 把刚上传的版本切到 100%
```

有账号级 Workers 权限和 `tju.pt` 的 Workers Routes Write 的人，也可以直接 `wrangler deploy`。

### 4. 部署后验证

1. 往 `TJUPT-Attachments-v2` 手动上传一个 `test.png` 和一个 `test.pdf`（key：`ab/cd/<剩余60位>.<扩展名>`）。
2. KV 里没有这个文件的键时，图片直接访问应返回 200：
   ```
   curl -I "https://files.tju.pt/test.png?file_id=<sha256>"
   ```
3. PDF 不带签名应返回 400：
   ```
   curl -I "https://files.tju.pt/test.pdf?file_id=<sha256>"
   ```
4. 用 SALT 算出的签名（`md5(ts + file_id + SALT)`）应能下载：
   ```
   curl -o /tmp/test.pdf "https://files.tju.pt/test.pdf?file_id=<sha256>&ts=<ts>&sign=<sign>"
   ```
5. 往 KV 写入 `<sha256>` → `blocked` 后，图片应返回 404 和占位图：
   ```
   wrangler kv key put --namespace-id=<id> <sha256> blocked
   curl -I "https://files.tju.pt/test.png?file_id=<sha256>"
   ```

## FILE_POLICY KV 约定

- 命名空间 `tjupt-files-policy`（id `012ef3f688ab4f3794c05358c860a775`），绑定名 `FILE_POLICY`。
- 键：文件的 sha256（64 位小写十六进制）。只有新桶（`storage = b2v2`）的文件会写。
- 由新后端通过 Cloudflare API 写入；管理员也可以用 `wrangler kv key put` 手动写。
- 每个请求先查 KV，再查边缘缓存，所以改了策略不受边缘缓存影响（KV 自身最多有 60 秒的读缓存）。

| 值 | 图片 | 非图片 |
|---|---|---|
| 没有键 | 公开，直接放行 | 公开（照常要 `ts` / `sign` 签名） |
| `signed` | 带有效的 `exp` + `sig` 签名，**或者** Referer 是 `tjupt.org` / `tju.pt` 及其子域名，才放行；否则返回 403 和占位图 | 不加额外要求（照常要 `ts` / `sign` 签名） |
| `blocked` | 404 和占位图 | 404 文字 |
| 其他任何值 | 当作 `blocked` | 当作 `blocked` |

### 图片签名（`signed` 策略）

图片地址带 `exp` 和 `sig` 两个参数：

- `exp`：到期时间（秒）。有效条件是 `now < exp ≤ now + 9×86400`。站点生成时用 `(floor(now / 86400) + 8) * 86400`，即 UTC 整天对齐、实际有效 7～8 天：同一天生成的地址相同，浏览器缓存和旧站 7 天的页面缓存都稳定。
- `sig`：`HMAC-SHA256(SALT, "<sha256>:<exp>")` 的十六进制前 32 位，小写。
- 参数缺失或格式不对，当作没有签名（不返回 400）。SALT 没配置时签名一律无效，只剩 Referer 一条路。

### Referer 检查

Referer 的 hostname 等于 `tjupt.org`、`tju.pt`，或者以 `.tjupt.org`、`.tju.pt` 结尾，才算本站（`evil-tjupt.org` 不算）。没有 Referer 就不算本站。

### 非图片文件

始终要 5 分钟有效的 `ts` / `sign` 签名（`sign = md5(ts + file_id + SALT)`）。`signed` 对非图片不加额外要求；`blocked` 和未知值返回 404。

### 缓存

- 没有键的文件：`Cache-Control: public, max-age=31536000`（不变）。
- `signed` 且放行的图片：`Cache-Control: private, max-age=31536000`。浏览器可以自己缓存，但代理、公司网关这类共享缓存不能存下来再发给别人。
- `blocked`、未知值以及 403：`Cache-Control: no-store`，浏览器不会记住被拒的结果，恢复访问后马上就能打开。
- 边缘缓存按对象存（缓存键 `https://files.tju.pt/__obj/<key>`），没有键的文件和 `signed` 的文件都会存，存进去的头一律是 `public`，返回前再按这次请求改成 `private`。命中边缘缓存之前已经查过 KV，所以缓存不会绕过策略。Range 请求不查也不写缓存。

## 本地测试

```bash
npm test
```
