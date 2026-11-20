import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.jsonc' },
        miniflare: {
          // FILE_POLICY KV 绑定：测试里按需操作
          kvNamespaces: ['FILE_POLICY'],
          bindings: {
            B2_KEY_ID: 'test-key-id',
            B2_APP_KEY: 'test-app-key',
            SALT: 'testsalt',
            B2_S3_ENDPOINT: 'https://s3.test',
            B2_REGION: 'us-west-002',
            B2_BUCKET: 'TJUPT-Attachments-v2',
            BASE_URL: 'https://tjupt.org',
            BROWSER_MAX_AGE: '31536000',
          },
        },
      },
    },
  },
})
