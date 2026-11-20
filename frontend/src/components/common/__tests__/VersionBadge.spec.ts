import { enableAutoUnmount, mount } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import VersionBadge from '../VersionBadge.vue'

const authStore = { isAdmin: false }
const appStore = {
  currentVersion: '0.2.23',
  latestVersion: '0.2.24',
  versionLoading: false,
  hasUpdate: true,
  releaseInfo: null,
  buildType: 'source',
  fetchVersion: vi.fn()
}

vi.mock('@/stores', () => ({
  useAuthStore: () => authStore,
  useAppStore: () => appStore
}))
vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ t: (key: string) => key }) }
})

const mountBadge = () => mount(VersionBadge, {
  props: { version: '0.2.22' },
  global: { plugins: [createPinia()], stubs: { Icon: true } }
})

enableAutoUnmount(afterEach)
afterEach(() => vi.unstubAllEnvs())

describe('VersionBadge display version', () => {
  beforeEach(() => {
    authStore.isAdmin = false
    vi.stubEnv('VITE_DISPLAY_VERSION', '')
  })

  it('shows the configured release label for regular users', () => {
    vi.stubEnv('VITE_DISPLAY_VERSION', ' 0.2.24-r27 ')
    expect(mountBadge().text()).toBe('0.2.24-r27')
  })

  it('shows the release label on the admin badge and the technical versions in update details', async () => {
    authStore.isAdmin = true
    vi.stubEnv('VITE_DISPLAY_VERSION', '0.2.24-r27')
    const wrapper = mountBadge()
    const badge = wrapper.get('button')
    expect(badge.text()).toBe('0.2.24-r27')

    await badge.trigger('click')
    expect(wrapper.text()).toContain('v0.2.23')
    expect(wrapper.text()).toContain('v0.2.24')
  })

  it('uses the public version without a configured release label', () => {
    expect(mountBadge().text()).toBe('v0.2.22')
  })

  it('uses the update service version on the admin badge without a label', () => {
    authStore.isAdmin = true
    expect(mountBadge().get('button').text()).toBe('v0.2.23')
  })
})
