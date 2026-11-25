<template>
  <fieldset class="space-y-2">
    <label class="flex items-center gap-2 text-sm font-medium text-gray-700 dark:text-gray-200">
      <input
        type="checkbox"
        data-testid="account-user-binding-toggle"
        class="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-dark-500"
        :checked="enabled"
        :aria-describedby="descriptionId"
        @change="emit('update:enabled', ($event.target as HTMLInputElement).checked)"
      />
      {{ t('admin.accounts.userBinding.title') }}
    </label>
    <p :id="descriptionId" class="text-xs text-gray-500 dark:text-gray-400">
      {{ t('admin.accounts.userBinding.description') }}
    </p>
    <template v-if="enabled">
      <ul v-if="modelValue.length" class="flex flex-wrap gap-2">
        <li
          v-for="id in modelValue"
          :key="id"
          class="inline-flex max-w-full items-center gap-2 rounded-md bg-gray-100 px-2 py-1 text-xs text-gray-700 dark:bg-dark-600 dark:text-gray-200"
        >
          <span class="truncate">{{ selectedLabels[id] ?? userIdLabel(id) }}</span>
          <button
            type="button"
            class="shrink-0 rounded text-gray-500 hover:text-red-600 dark:hover:text-red-400"
            :aria-label="t('admin.accounts.userBinding.removeUser', { user: selectedLabels[id] ?? userIdLabel(id) })"
            @click="emit('update:modelValue', modelValue.filter(userId => userId !== id))"
          >
            <Icon name="x" size="xs" />
          </button>
        </li>
      </ul>
      <Select
        :model-value="null"
        :options="options"
        :aria-label="t('admin.accounts.userBinding.search')"
        :placeholder="t('admin.accounts.userBinding.search')"
        :search-placeholder="t('admin.accounts.userBinding.search')"
        :empty-text="t(searched ? 'admin.accounts.userBinding.noUsers' : 'admin.accounts.userBinding.searchPrompt')"
        :loading="loading"
        remote
        @search="searchUsers"
        @update:model-value="selectUser"
      />
      <p v-if="searchFailed" role="alert" class="text-xs text-red-600 dark:text-red-400">
        {{ t('admin.accounts.userBinding.searchFailed') }}
      </p>
    </template>
  </fieldset>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import Select from '@/components/common/Select.vue'
import Icon from '@/components/icons/Icon.vue'

const props = defineProps<{ enabled: boolean; modelValue: number[] }>()
const emit = defineEmits<{
  'update:enabled': [value: boolean]
  'update:modelValue': [value: number[]]
}>()
const { t } = useI18n()
const descriptionId = useId()
const selectedLabels = ref<Record<number, string>>({})
const results = ref<{ value: number; label: string }[]>([])
const loading = ref(false)
const searched = ref(false)
const searchFailed = ref(false)
let searchController: AbortController | undefined

const options = computed(() => results.value.filter(user => !props.modelValue.includes(user.value)))
const userIdLabel = (id: number) => t('admin.accounts.userBinding.userId', { id })
const userLabel = (user: { id: number; email: string }) => `${user.email} (#${user.id})`

function clearSearch() {
  searchController?.abort()
  searchController = undefined
  results.value = []
  loading.value = false
  searched.value = false
  searchFailed.value = false
}

async function searchUsers(query: string) {
  clearSearch()
  if (!query || !props.enabled) return
  const controller = new AbortController()
  searchController = controller
  loading.value = true
  try {
    const { items } = await adminAPI.users.list(1, 20, {
      search: query,
      status: 'active',
      include_subscriptions: false
    }, { signal: controller.signal })
    if (!controller.signal.aborted) {
      results.value = items.map(user => ({ value: user.id, label: userLabel(user) }))
      searched.value = true
    }
  } catch {
    if (!controller.signal.aborted) searchFailed.value = true
  } finally {
    if (!controller.signal.aborted) loading.value = false
  }
}

function selectUser(value: string | number | boolean | null) {
  const user = options.value.find(option => option.value === value)
  if (!user) return
  selectedLabels.value[user.value] = user.label
  emit('update:modelValue', [...props.modelValue, user.value])
  clearSearch()
}

watch(() => [props.enabled, props.modelValue] as const, async ([enabled, ids], _, onCleanup) => {
  if (!enabled) {
    clearSearch()
    return
  }
  let stale = false
  onCleanup(() => { stale = true })
  await Promise.all(ids.filter(id => !selectedLabels.value[id]).map(async id => {
    try {
      const user = await adminAPI.users.getById(id, true)
      if (!stale) selectedLabels.value[id] = userLabel(user)
    } catch {
      // Keep the existing ID selected when lookup is unavailable.
    }
  }))
}, { immediate: true })

onUnmounted(clearSearch)
</script>
