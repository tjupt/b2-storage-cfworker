const md5 = require('md5')
const B2 = require('backblaze-b2')

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

const corsFileTypes = ['png', 'jpg', 'gif', 'jpeg', 'webp']
const removeHeaders = [
  'x-bz-content-sha1',
  'x-bz-file-id',
  'x-bz-file-name',
  'x-bz-info-src_last_modified_millis',
  'X-Bz-Upload-Timestamp',
  'Expires',
]
const expiration = 31536000
const baseUrl = process.env.BASE_URL
const salt = process.env.SALT
const b2Domain = process.env.B2_DOMAIN
const b2Bucket = process.env.B2_BUCKET
const b2AccountId = process.env.B2_ACCOUNT_ID
const b2MasterApplicationKey = process.env.B2_MASTER_APPLICATION_KEY
const b2BucketId = process.env.B2_BUCKET_ID

const uploadResultCallbackEndpoint = baseUrl + '/attachment_callback.php'

const fixHeaders = function(cors, status, headers) {
  let newHeaders = new Headers(headers)

  // 1. 如果是图片，添加cors头
  if (cors) {
    newHeaders.set('Access-Control-Allow-Origin', '*')
  }

  // 添加浏览器缓存头
  newHeaders.set('Cache-Control', 'public, max-age=' + expiration)

  // 添加ETag头
  const ETag =
    newHeaders.get('x-bz-content-sha1') ||
    newHeaders.get('x-bz-info-src_last_modified_millis') ||
    newHeaders.get('x-bz-file-id')
  if (ETag) {
    newHeaders.set('ETag', ETag)
  }

  // 移除B2带来的不必要的headers
  removeHeaders.forEach(header => {
    newHeaders.delete(header)
  })

  return newHeaders
}

const notFound = function(isImage, pathname, origin) {
  if (isImage) {
    return Response.redirect(origin + '/404.webp', 301)
  } else {
    return new Response(`找不到此附件[${pathname}]，请重试或联系管理组`, {
      status: 404,
    })
  }
}

/**
 * @param {Request} request
 */
async function handleRequest(request) {
  const cache = caches.default
  const requestUrl = new URL(request.url)
  const ext = (requestUrl.pathname.split('.').pop() ?? '').toLowerCase()
  const isImage = corsFileTypes.includes(ext)
  const fileId = requestUrl.searchParams.get('file_id') ?? ''
  let filePath = '/404.webp'

  // 1. 拒绝非法请求
  if (!ext || requestUrl.pathname === ext) {
    return Response.redirect(baseUrl, 302)
  }

  // 2. 非图片请求验签 md5(timestamp + fileId + salt)
  if (!isImage) {
    // verify the signature of the query
    const timestamp = requestUrl.searchParams.get('ts') ?? 0
    const trueSign = md5(`${timestamp}${fileId}${salt}`)

    if (
      timestamp < Date.now() / 1000 - 300 ||
      trueSign !== requestUrl.searchParams.get('sign')
    ) {
      return new Response('链接已过期，请返回原页面重新下载', { status: 400 })
    }
  }

  // 3. 判断是否为404，如果不是的话更新filePath
  if (requestUrl.pathname !== '/404.webp' || fileId !== '') {
    filePath =
      '/' +
      fileId.slice(0, 2) +
      '/' +
      fileId.slice(2, 4) +
      '/' +
      fileId.slice(4) +
      '.' +
      ext
  }

  // 4. 构造b2链接
  const b2Url = new URL(`https://${b2Domain}/file/${b2Bucket}${filePath}`)

  // 5. 查询Cloudflare缓存
  let response = await cache.match(b2Url.toString())
  if (response) {
    // 5.1. 如果有缓存
    let newHeaders = fixHeaders(isImage, response.status, response.headers)
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    })
  }

  // 5.2. 如果无缓存，构造请求
  response = await fetch(new Request(b2Url.toString()))

  if (response.status === 200) {
    let newHeaders = fixHeaders(isImage, response.status, response.headers)
    response = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    })

    // 写缓存
    await cache.put(b2Url.toString(), response.clone())

    return response
  } else {
    // 返回404
    return notFound(isImage, requestUrl.pathname, requestUrl.origin)
  }
}

async function handleUpload(request) {
  // 0. 验签，获取参数
  const requestUrl = new URL(request.url)
  const fileSHA1 = requestUrl.searchParams.get('file_sha1') ?? ''
  const fileSHA256 = requestUrl.searchParams.get('file_sha256') ?? ''
  const attachmentId = requestUrl.searchParams.get('attachment_id') ?? ''
  const filename = requestUrl.searchParams.get('filename') ?? ''
  const sign = requestUrl.searchParams.get('sign') ?? ''

  const data = request.formData()

  const ext = (filename.split('.').pop() ?? '').toLowerCase()

  const trueSign = md5(`${fileSHA1}${fileSHA256}${attachmentId}${salt}`)
  if (trueSign !== sign) {
    return new Response(
      JSON.stringify({ msg: '验签错误，请重试或联系管理组' }, null, 2),
      {
        status: 401,
        statusText: 'Unauthorized',
        headers: {
          'content-type': 'application/json;charset=UTF-8',
        },
      },
    )
  }

  let b2 = new B2({
    accountId: b2AccountId,
    masterApplicationKey: b2MasterApplicationKey,
  })

  // 1. 鉴权，优先从KV里取数据
  let authorizationToken = B2KV.get('B2AuthorizationToken')
  let apiUrl = B2KV.get('B2ApiUrl')
  let downloadUrl = B2KV.get('B2DownloadUrl')
  if (authorizationToken === null) {
    const authorizeResp = await b2.authorize()
    if (authorizeResp.status !== 200) {
      return new Response(
        JSON.stringify(
          { msg: '无法与云端存储鉴权，请重试或将此错误汇报至管理组' },
          null,
          2,
        ),
        {
          status: authorizeResp.status,
          statusText: authorizeResp.statusText,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
          },
        },
      )
    }

    authorizationToken = authorizeResp.data.authorizationToken
    apiUrl = authorizeResp.data.apiUrl
    downloadUrl = authorizeResp.data.downloadUrl

    const KVPromise0 = B2KV.put('B2AuthorizationToken', authorizationToken, {
      expirationTtl: 24 * 60 * 60,
    })
    const KVPromise1 = B2KV.put('B2ApiUrl', apiUrl, {
      expirationTtl: 24 * 60 * 60,
    })
    const KVPromise2 = B2KV.put('B2DownloadUrl', downloadUrl, {
      expirationTtl: 24 * 60 * 60,
    })

    await Promise.all([KVPromise0, KVPromise1, KVPromise2])
  } else {
    b2.authorizationToken = authorizationToken
    b2.apiUrl = apiUrl
    b2.downloadUrl = downloadUrl
  }

  let uploadUrl = B2KV.get('B2UploadUrl')
  let uploadAuthorizationToken = B2KV.get('B2UploadAuthorizationToken')
  if (uploadUrl === null) {
    const getUploadUrlResp = await b2.getUploadUrl({
      bucketId: b2BucketId,
    })

    uploadUrl = getUploadUrlResp.data.uploadUrl
    uploadAuthorizationToken = getUploadUrlResp.data.authorizationToken

    const KVPromise0 = B2KV.put('B2UploadUrl', uploadUrl, {
      expirationTtl: 24 * 60 * 60,
    })
    const KVPromise1 = B2KV.put(
      'B2UploadAuthorizationToken',
      uploadAuthorizationToken,
      { expirationTtl: 24 * 60 * 60 },
    )

    await Promise.all([KVPromise0, KVPromise1])
  }

  const filePath =
    '/' +
    fileSHA256.slice(0, 2) +
    '/' +
    fileSHA256.slice(2, 4) +
    '/' +
    fileSHA256.slice(4) +
    '.' +
    ext
  const uploadFileResp = await b2.uploadFile({
    uploadUrl: uploadUrl,
    uploadAuthToken: uploadAuthorizationToken,
    fileName: filePath,
    data: data.file,
    hash: fileSHA1,
  })

  let { readable, writable } = new TransformStream()
  uploadFileResp.body.pipeTo(writable)
  readable
    .getReader()
    .read()
    .then(
      ({ done, value }) =>
        async function() {
          if (done) {
            await fetch(uploadResultCallbackEndpoint)
          }
        },
    )

  return new Response(JSON.stringify({ msg: '上传成功' }, null, 2), {
    status: 200,
    statusText: 'OK',
    headers: {
      'content-type': 'application/json;charset=UTF-8',
    },
  })
}
