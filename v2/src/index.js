import { AwsClient } from 'aws4fetch'

const IMAGE_EXTS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp'])
const FILE_ID_RE = /^[0-9a-f]{64}$/

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
function applyPerRequestHeaders(headers, isImage, displayName, browserMaxAge) {
  headers.set('Cache-Control', `public, max-age=${browserMaxAge ?? '31536000'}`)
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

    // 非图片验签
    if (!isImage) {
      const ts = url.searchParams.get('ts') ?? ''
      const sign = url.searchParams.get('sign') ?? ''
      const tsNum = parseInt(ts, 10)
      const now = Math.floor(Date.now() / 1000)
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

    // BLOCKED 检查（在查缓存之前，绑定可选）
    if (env.BLOCKED) {
      const blocked = await env.BLOCKED.get(fileId)
      if (blocked !== null) {
        return new Response('此附件已被屏蔽', { status: 404 })
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

    applyPerRequestHeaders(headers, isImage, displayName, env.BROWSER_MAX_AGE)

    const response = new Response(upstream.body, {
      status: upstream.status,
      headers,
    })

    // 只有 GET + 非 Range + 200 才写缓存
    if (isGet && !isRange && upstream.status === 200) {
      // 写入缓存时去掉 Content-Disposition（避免缓存的文件名影响后续请求）
      const cacheHeaders = new Headers(headers)
      cacheHeaders.delete('Content-Disposition')
      cacheHeaders.delete('Access-Control-Allow-Origin')
      const cacheResponse = new Response(response.clone().body, {
        status: upstream.status,
        headers: cacheHeaders,
      })
      ctx.waitUntil(caches.default.put(cacheKey, cacheResponse))
    }

    return response
  },
}
