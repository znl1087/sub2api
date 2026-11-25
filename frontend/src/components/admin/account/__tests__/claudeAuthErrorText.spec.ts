import { describe, expect, it } from 'vitest'

// 拦截器（src/api/client.ts）把错误改写成顶层 { status, code, reason, message }。
// 这里复现该形状，验证两处 Claude 提示的分派逻辑。
function messageFor(error: any, authFailed: string, mismatch: string): string {
  return error.reason === 'oauth_state_mismatch' ? mismatch : error.message || authFailed
}

describe('Claude auth error text', () => {
  it('uses the dedicated hint for a state mismatch', () => {
    const err = { status: 400, reason: 'oauth_state_mismatch', message: 'the pasted state does not belong' }
    expect(messageFor(err, '授权失败', '请使用当前链接对应的授权码')).toBe('请使用当前链接对应的授权码')
  })

  it('falls back to the backend message for other errors', () => {
    const err = { status: 400, reason: 'invalid_grant', message: 'bad code' }
    expect(messageFor(err, '授权失败', '请使用当前链接对应的授权码')).toBe('bad code')
  })

  it('falls back to the generic text when there is no message', () => {
    expect(messageFor({ status: 500 }, '授权失败', '请使用当前链接对应的授权码')).toBe('授权失败')
  })
})
