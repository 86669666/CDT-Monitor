import { defineConfig } from '@playwright/test'

const port = 43212
const localURL = `http://127.0.0.1:${port}`

export default defineConfig({
  testDir: './tests',
  timeout: 90_000,
  retries: 0,
  workers: 1,
  use: {
    baseURL: process.env.CDT_E2E_URL || localURL,
    channel: 'chrome',
    viewport: { width: 1440, height: 1000 },
    locale: 'zh-CN',
    colorScheme: 'light',
  },
  webServer: process.env.CDT_E2E_URL
    ? undefined
    : {
        command: `npx vite --host 127.0.0.1 --port ${port} --strictPort`,
        url: localURL,
        reuseExistingServer: true,
        timeout: 120_000,
      },
})
