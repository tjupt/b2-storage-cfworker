# b2-storage-cfworker

这个仓库包含两个独立的 Cloudflare Worker：

## 根目录：usercontent.tju.pt（旧桶，不要改动）

`src/index.js` 是为 `usercontent.tju.pt` 服务的旧 Worker，读取公开桶 `TJUPT-Attachments`。
**不要修改根目录下的 `src/`、`package.json`、`webpack.config.js`、`wrangler_example.toml`**，部署方式不变（webpack 打包，wrangler 旧格式配置）。

## `v2/` 目录：files.tju.pt（新私有桶）

新 Worker，为 `files.tju.pt` 服务，读取私有桶 `TJUPT-Attachments-v2`。详见 [v2/README.md](v2/README.md)。

---

## Reference

- https://gist.github.com/steveyiyo/d7e5ed19ed2a63c9a970d44a5d97db22
