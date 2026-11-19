# files.tju.pt Worker

Cloudflare Worker，为 `files.tju.pt` 提供新私有桶（`TJUPT-Attachments-v2`）的文件访问。

## 部署步骤

```bash
cd v2
npm ci
wrangler login
```

### 1. 创建 KV 命名空间（可选，用于屏蔽文件）

```bash
wrangler kv namespace create BLOCKED
```

把输出的 `id` 填进 `wrangler.jsonc` 里 `kv_namespaces[0].id`，替换掉占位符。
如果暂时不需要屏蔽功能，可以把整个 `kv_namespaces` 段删掉，Worker 会跳过 BLOCKED 检查。

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

1. 往 `TJUPT-Attachments-v2` 手动上传一个 `test.png`（key: `ab/cd/<剩余60位>.png`）和一个 `test.pdf`（key: 同规则 `.pdf`）。
2. 图片直接访问应返回 200：
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
5. 往 BLOCKED KV 写入 `<sha256>` → `1` 后，图片访问应返回 404：
   ```
   wrangler kv key put --namespace-id=<id> <sha256> 1
   curl -I "https://files.tju.pt/test.png?file_id=<sha256>"
   ```

## BLOCKED KV 约定

- Key：文件的 sha256（64 位小写十六进制）
- Value：任意字符串（如 `1`）
- 由新后端通过 Cloudflare API 写入；管理员也可以用 `wrangler kv key put` 手动写入。
- BLOCKED 检查在边缘缓存之前，停止访问立即生效，不受边缘缓存影响。

## 本地测试

```bash
npm test
```
