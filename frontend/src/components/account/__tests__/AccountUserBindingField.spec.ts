import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import AccountUserBindingField from '../AccountUserBindingField.vue'
import Select from '@/components/common/Select.vue'

const { listUsers, getUser } = vi.hoisted(() => ({
  listUsers: vi.fn(),
  getUser: vi.fn(),
}))

vi.mock('@/api/admin', () => ({
  adminAPI: { users: { list: listUsers, getById: getUser } }
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({ t: (key: string) => key })
}))

describe('AccountUserBindingField', () => {
  beforeEach(() => {
    listUsers.mockReset()
    getUser.mockReset()
  })

  it('loads selected labels and appends a searched user without duplicating existing users', async () => {
    const selectedUser = { id: 42, email: 'selected@example.com' }
    const nextUser = { id: 53, email: 'new@example.com' }
    getUser.mockResolvedValue(selectedUser)
    listUsers.mockResolvedValue({ items: [selectedUser, nextUser] })
    const wrapper = mount(AccountUserBindingField, {
      props: { enabled: true, modelValue: [selectedUser.id] },
      global: { stubs: { Select: true, Icon: true } }
    })

    await flushPromises()
    expect(wrapper.text()).toContain('selected@example.com (#42)')
    const select = wrapper.getComponent(Select)
    select.vm.$emit('search', 'example.com')
    await flushPromises()
    expect(listUsers).toHaveBeenCalledWith(1, 20, {
      search: 'example.com',
      status: 'active',
      include_subscriptions: false
    }, { signal: expect.any(AbortSignal) })
    expect(select.props('options')).toEqual([{ value: 53, label: 'new@example.com (#53)' }])

    select.vm.$emit('update:modelValue', 53)
    expect(wrapper.emitted('update:modelValue')).toEqual([[[42, 53]]])
    await wrapper.setProps({ modelValue: [42, 53] })
    expect(wrapper.text()).toContain('new@example.com (#53)')
    await wrapper.get('li button').trigger('click')
    expect(wrapper.emitted('update:modelValue')?.[1]).toEqual([[53]])
    wrapper.unmount()
  })
})
