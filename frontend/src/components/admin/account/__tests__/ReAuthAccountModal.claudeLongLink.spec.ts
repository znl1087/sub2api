import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const source = readFileSync(
  resolve(process.cwd(), 'src/components/admin/account/ReAuthAccountModal.vue'),
  'utf8'
)

describe('ReAuthAccountModal Claude re-auth long-link toggle', () => {
  it('forwards the flow selection to the Claude authorize call', () => {
    // 切换开关在 OAuthAuthorizationFlow 里，重新授权必须把它带进请求，
    // 否则按钮文案会变、请求仍生成短链。
    expect(source).toContain('const handleGenerateUrl = async (longLink = false) => {')
    expect(source).toContain('claudeOAuth.generateAuthUrl(addMethod.value, props.account.proxy_id, longLink)')
  })

  it('keeps the toggle reachable from the re-auth flow', () => {
    expect(source).toContain('@generate-url="handleGenerateUrl"')
  })
})
