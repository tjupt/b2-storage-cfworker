import { AwsClient } from 'aws4fetch'

const IMAGE_EXTS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp'])
const FILE_ID_RE = /^[0-9a-f]{64}$/

// 403 占位图：SVG "仅限站内查看"
const BLOCKED_IMAGE_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60" viewBox="0 0 200 60">
  <rect width="200" height="60" fill="#f0f0f0"/>
  <text x="100" y="36" font-family="sans-serif" font-size="14" fill="#666" text-anchor="middle">仅限站内查看</text>
</svg>`

// RFC 5987 编码：只编码非 attr-char 字符
function encodeRfc5987(str) {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase(),
  )
}

// 定长比较（防时序攻击）
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return diff === 0
}

async function md5Hex(str) {
  const data = new TextEncoder().encode(str)
  const buf = await crypto.subtle.digest('MD5', data)
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// HMAC-SHA256，返回十六进制前 32 位小写（sig 验证用）
async function hmacSha256Prefix32(salt, message) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(salt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const buf = await crypto.subtle.sign(
    'HMAC',
    keyMaterial,
    new TextEncoder().encode(message),
  )
  const hex = Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  return hex.slice(0, 32)
}

function stripB2Headers(upstreamHeaders) {
  const out = new Headers()
  upstreamHeaders.forEach((value, name) => {
    if (
      !name.startsWith('x-amz-') &&
      !name.startsWith('x-bz-') &&
      name !== 'expires'
    ) {
      out.set(name, value)
    }
  })
  // 显式补 ETag（部分环境 forEach 可能跳过此头）
  const etag = upstreamHeaders.get('etag')
  if (etag && !out.has('etag')) out.set('ETag', etag)
  return out
}

// 按本次请求设置与请求相关的头（缓存命中和回源都调用）
function applyPerRequestHeaders(headers, isImage, displayName, browserMaxAge, isSigned) {
  // signed 图片用 private：允许浏览器自己缓存，但阻止中间的共享缓存（代理、公司网关）把图片存下来发给别人
  const cacheDirective = isImage && isSigned ? 'private' : 'public'
  headers.set('Cache-Control', `${cacheDirective}, max-age=${browserMaxAge ?? '31536000'}`)
  headers.set('X-Content-Type-Options', 'nosniff')
  if (isImage) {
    headers.set('Access-Control-Allow-Origin', '*')
    headers.delete('Content-Disposition')
  } else {
    headers.delete('Access-Control-Allow-Origin')
    headers.set(
      'Content-Disposition',
      `attachment; filename*=UTF-8''${encodeRfc5987(displayName)}`,
    )
  }
}

// 检查请求是否带有效签名（exp + sig）
// 有效条件：now < exp <= now + 9*86400，sig = HMAC-SHA256(SALT, "<sha256>:<exp>") 前 32 位
// 参数缺失、格式不对或 SALT 未配置返回 false，不报 400
async function hasValidImageSig(url, fileId, salt, now) {
  if (!salt) return false
  const expStr = url.searchParams.get('exp') ?? ''
  const sig = url.searchParams.get('sig') ?? ''
  if (!expStr || !sig) return false
  if (!/^\d{1,12}$/.test(expStr)) return false
  const exp = parseInt(expStr, 10)
  if (exp <= now || exp > now + 9 * 86400) return false
  const expected = await hmacSha256Prefix32(salt, `${fileId}:${expStr}`)
  return timingSafeEqual(expected, sig.toLowerCase())
}

// 检查 Referer 是否是本站（tjupt.org / tju.pt 及子域名）
function isOwnSiteReferer(request) {
  const referer = request.headers.get('Referer') ?? ''
  if (!referer) return false
  let hostname
  try {
    hostname = new URL(referer).hostname
  } catch {
    return false
  }
  return (
    hostname === 'tjupt.org' ||
    hostname === 'tju.pt' ||
    hostname.endsWith('.tjupt.org') ||
    hostname.endsWith('.tju.pt')
  )
}

export default {
  async fetch(request, env, ctx) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method Not Allowed', { status: 405 })
    }

    const url = new URL(request.url)
    const pathname = url.pathname

    // 取扩展名
    const lastSegment = pathname.split('/').pop() ?? ''
    const dotIdx = lastSegment.lastIndexOf('.')
    if (dotIdx < 0 || dotIdx === lastSegment.length - 1) {
      return Response.redirect(env.BASE_URL, 302)
    }
    const ext = lastSegment.slice(dotIdx + 1).toLowerCase()

    // 解码显示名（pathname 已被百分号编码，要先 decode）
    let displayName
    try {
      displayName = decodeURIComponent(lastSegment)
    } catch {
      displayName = lastSegment
    }

    // 校验 file_id
    const fileId = url.searchParams.get('file_id') ?? ''
    if (!FILE_ID_RE.test(fileId)) {
      return Response.redirect(env.BASE_URL, 302)
    }

    const isImage = IMAGE_EXTS.has(ext)
    const now = Math.floor(Date.now() / 1000)

    // 非图片验 ts/sign（5 分钟窗口）
    if (!isImage) {
      const ts = url.searchParams.get('ts') ?? ''
      const sign = url.searchParams.get('sign') ?? ''
      const tsNum = parseInt(ts, 10)
      if (!ts || isNaN(tsNum) || tsNum < now - 300 || tsNum > now + 60) {
        return new Response('链接已过期，请返回原页面重新下载', { status: 400 })
      }
      const expected = await md5Hex(`${ts}${fileId}${env.SALT}`)
      if (!timingSafeEqual(expected, sign.toLowerCase())) {
        return new Response('链接已过期，请返回原页面重新下载', { status: 400 })
      }
    }

    // 对象 key
    const key = `${fileId.slice(0, 2)}/${fileId.slice(2, 4)}/${fileId.slice(4)}.${ext}`

    // FILE_POLICY 检查（在查边缘缓存之前）
    // 没有键：放行。signed：图片需满足签名或本站 Referer。blocked 及其他任何值：一律 404。
    let isSigned = false
    if (env.FILE_POLICY) {
      const policy = await env.FILE_POLICY.get(fileId)
      if (policy === 'blocked' || (policy !== null && policy !== 'signed')) {
        // blocked 或未知值
        if (isImage) {
          return new Response(BLOCKED_IMAGE_SVG, {
            status: 404,
            headers: {
              'Content-Type': 'image/svg+xml',
              'Cache-Control': 'no-store',
            },
          })
        }
        return new Response('此附件已被屏蔽', { status: 404 })
      }
      if (policy === 'signed') {
        if (isImage) {
          const sigOk = await hasValidImageSig(url, fileId, env.SALT, now)
          const refOk = isOwnSiteReferer(request)
          if (!sigOk && !refOk) {
            return new Response(BLOCKED_IMAGE_SVG, {
              status: 403,
              headers: {
                'Content-Type': 'image/svg+xml',
                'Cache-Control': 'no-store',
              },
            })
          }
          isSigned = true
        }
        // 非图片：signed 策略下不加额外要求（ts/sign 已在上面验过）
      }
    }

    const isRange = request.headers.has('range')
    const isGet = request.method === 'GET'
    // 边缘缓存 key：只按对象，不带查询参数
    const cacheKey = `https://files.tju.pt/__obj/${key}`

    // Range 请求直接跳过缓存（不查不写）
    if (!isRange) {
      const cached = await caches.default.match(cacheKey)
      if (cached) {
        // 缓存命中：用缓存的 body 和底层头，但重新按本次请求设置相关头
        const headers = new Headers(cached.headers)
        applyPerRequestHeaders(
          headers,
          isImage,
          displayName,
          env.BROWSER_MAX_AGE,
          isSigned,
        )
        return new Response(cached.body, { status: cached.status, headers })
      }
    }

    // 用 aws4fetch 签名请求 B2 S3
    const aws = new AwsClient({
      accessKeyId: env.B2_KEY_ID,
      secretAccessKey: env.B2_APP_KEY,
      service: 's3',
      region: env.B2_REGION,
    })

    const b2Url = `${env.B2_S3_ENDPOINT}/${env.B2_BUCKET}/${key}`

    const upstreamReq = new Request(b2Url, {
      method: request.method,
      headers: isRange ? { range: request.headers.get('range') } : {},
    })
    const signedReq = await aws.sign(upstreamReq)
    const upstream = await fetch(signedReq)

    if (upstream.status === 404) {
      return new Response('找不到此附件，请重试或联系管理组', { status: 404 })
    }
    if (upstream.status === 403) {
      console.error(
        `[files-worker] B2 403 for key ${key} — check B2_KEY_ID/B2_APP_KEY permissions`,
      )
      return new Response('上游存储错误，请稍后重试', { status: 502 })
    }
    if (upstream.status !== 200 && upstream.status !== 206) {
      return new Response('上游存储错误，请稍后重试', { status: 502 })
    }

    // 组装响应头
    const headers = stripB2Headers(upstream.headers)

    // 透传 ETag（stripB2Headers 已复制；无 etag 时从 x-bz-* 回退）
    if (!headers.has('etag')) {
      const bz =
        upstream.headers.get('x-bz-content-sha1') ||
        upstream.headers.get('x-bz-file-id')
      if (bz) headers.set('ETag', bz)
    }

    applyPerRequestHeaders(headers, isImage, displayName, env.BROWSER_MAX_AGE, isSigned)

    const response = new Response(upstream.body, {
      status: upstream.status,
      headers,
    })

    // 只有 GET + 非 Range + 200 才写边缘缓存
    if (isGet && !isRange && upstream.status === 200) {
      // 写入缓存时去掉 Content-Disposition 和 Access-Control-Allow-Origin
      // 以及 signed 图片的 private 指令——缓存里只存 public，让后续公开请求也能命中
      const cacheHeaders = new Headers(headers)
      cacheHeaders.delete('Content-Disposition')
      cacheHeaders.delete('Access-Control-Allow-Origin')
      if (isSigned) {
        cacheHeaders.set('Cache-Control', `public, max-age=${env.BROWSER_MAX_AGE ?? '31536000'}`)
      }
      const cacheResponse = new Response(response.clone().body, {
        status: upstream.status,
        headers: cacheHeaders,
      })
      ctx.waitUntil(caches.default.put(cacheKey, cacheResponse))
    }

    return response
  },
}
