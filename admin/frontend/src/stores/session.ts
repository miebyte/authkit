import { ref } from 'vue'
import type { AccountIdentity } from '@/types/admin'

const storageKey = 'authkit.admin.token'

function savedToken(): string {
  try {
    return sessionStorage.getItem(storageKey) ?? ''
  } catch {
    return ''
  }
}

const token = ref(savedToken())
const account = ref<AccountIdentity | null>(null)
const status = ref<'checking' | 'guest' | 'authenticated'>(token.value ? 'checking' : 'guest')

export const session = {
  token,
  account,
  status,

  establish(value: string, identity: AccountIdentity): void {
    token.value = value
    account.value = identity
    status.value = 'authenticated'
    try {
      sessionStorage.setItem(storageKey, value)
    } catch {
      // 存储不可用时，仅在当前页面保留会话。
    }
  },

  clear(): void {
    token.value = ''
    account.value = null
    status.value = 'guest'
    try {
      sessionStorage.removeItem(storageKey)
    } catch {
      // 存储不可用时，响应式状态仍需清除。
    }
  },

  markGuest(): void {
    account.value = null
    status.value = 'guest'
  },

  markAuthenticated(identity: AccountIdentity): void {
    if (!token.value) return
    account.value = identity
    status.value = 'authenticated'
  },
}
