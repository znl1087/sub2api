import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const flow = readFileSync(
  resolve(process.cwd(), 'src/components/account/OAuthAuthorizationFlow.vue'),
  'utf8'
)
const reAuth = readFileSync(
  resolve(process.cwd(), 'src/components/admin/account/ReAuthAccountModal.vue'),
  'utf8'
)

const create = readFileSync(
  resolve(process.cwd(), 'src/components/account/CreateAccountModal.vue'),
  'utf8'
)

describe('Claude re-auth long-link toggle', () => {
  it('forwards the flow selection to the Claude authorize call', () => {
    // 切换开关在 OAuthAuthorizationFlow 里，重新授权必须把它带进请求，
    // 否则按钮文案会变、请求仍生成短链。
    expect(reAuth).toContain('const handleGenerateUrl = async (longLink = false) => {')
    expect(reAuth).toContain('claudeOAuth.generateAuthUrl(addMethod.value, props.account.proxy_id, longLink)')
    expect(reAuth).toContain('@generate-url="handleGenerateUrl"')
  })

  it('emits the current selection on first generate and on retry', () => {
    expect(flow).toContain("emit('generate-url', useLongLink.value)")
  })

  it('surfaces the backend message instead of the generic failure', () => {
    // 后端错误体是 { message, reason }，读 detail 会永远落空。
    expect(reAuth).toContain('error.response?.data?.message || error.response?.data?.detail');
    expect(create).toContain('error.response?.data?.message || error.response?.data?.detail');
  })

  it('shows the toggle on the Claude form only', () => {
    // 其他平台的生成接口不认 long_link，按钮必须限定在 Claude 表单。
    expect(flow).toContain(`v-if="platform === 'anthropic'"`)
    expect(flow).toContain('@click="toggleLongLink"')
  })
})
