<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterView, useRoute, useRouter } from 'vue-router'
import { getMe, logout } from '@/api/admin'
import { ApiError, errorMessage } from '@/api/request'
import AdminLayout from '@/components/layout/AdminLayout.vue'
import { session } from '@/stores/session'
import { brandTitle } from '@/utils/brand'

interface RefreshableView {
  refresh: () => Promise<void>
}

const route = useRoute()
const router = useRouter()
const status = session.status
const account = session.account
const activeView = ref<RefreshableView | null>(null)
const refreshing = ref(false)
const loggingOut = ref(false)
const bootError = ref('')
const notice = ref('')
const noticeError = ref(false)
let noticeTimer: number | undefined

function loginTarget(): { name: string; query?: { redirect: string } } {
  return route.name === 'accounts' || route.name === 'blacklist'
    ? { name: 'login', query: { redirect: route.path } }
    : { name: 'login' }
}

function showNotice(message: string, isError = false): void {
  window.clearTimeout(noticeTimer)
  notice.value = message
  noticeError.value = isError
  noticeTimer = window.setTimeout(() => { notice.value = '' }, 5000)
}

async function bootstrap(): Promise<void> {
  bootError.value = ''
  await router.isReady()
  if (!session.token.value) {
    session.markGuest()
    if (route.name !== 'login') await router.replace(loginTarget())
    return
  }

  try {
    const identity = await getMe()
    session.markAuthenticated(identity)
    if (route.name === 'login' || route.path === '/') {
      await router.replace('/overview')
    }
  } catch (cause: unknown) {
    if (cause instanceof ApiError && cause.status === 403) {
      session.clear()
      showNotice('当前账号没有超管权限。', true)
    } else if (session.status.value === 'guest') {
      showNotice('登录已失效，请重新验证邮箱。', true)
    } else {
      bootError.value = errorMessage(cause)
      return
    }
    await router.replace(loginTarget())
  }
}

async function refreshPage(): Promise<void> {
  if (refreshing.value || !activeView.value) return
  refreshing.value = true
  try {
    await activeView.value.refresh()
  } finally {
    refreshing.value = false
  }
}

async function handleLogout(): Promise<void> {
  if (loggingOut.value) return
  loggingOut.value = true
  try {
    await logout()
    session.clear()
    showNotice('已退出后台。')
    await router.replace('/login')
  } catch (cause: unknown) {
    if (session.status.value === 'authenticated') {
      showNotice(`退出失败：${errorMessage(cause)}`, true)
    }
  } finally {
    loggingOut.value = false
  }
}

watch(status, (next, previous) => {
  if (next === 'guest' && previous === 'authenticated') {
    if (loggingOut.value) return
    showNotice('登录已失效，请重新验证邮箱。', true)
    void router.replace(loginTarget())
  }
})

watch(() => route.name, (name) => {
  const label = name === 'overview' ? '概览' : name === 'accounts' ? '账号管理' : name === 'blacklist' ? '黑名单' : '登录'
  document.title = `${label} · ${brandTitle} 超管后台`
}, { immediate: true })

onMounted(bootstrap)
onBeforeUnmount(() => window.clearTimeout(noticeTimer))
</script>

<template>
  <div v-if="status === 'checking'" class="bootstrap-screen" role="status">
    <div class="bootstrap-card">
      <span class="brand-mark" aria-hidden="true">A</span>
      <template v-if="bootError">
        <h1>暂时无法验证登录状态</h1>
        <p>{{ bootError }}</p>
        <button class="button button-primary" type="button" @click="bootstrap">重试</button>
      </template>
      <p v-else>正在验证登录状态…</p>
    </div>
  </div>

  <RouterView v-else-if="route.name === 'login'" />

  <AdminLayout
    v-else-if="status === 'authenticated' && account"
    :account="account"
    :refreshing="refreshing"
    :logging-out="loggingOut"
    @refresh="refreshPage"
    @logout="handleLogout"
  >
    <RouterView v-slot="{ Component }">
      <component :is="Component" ref="activeView" />
    </RouterView>
  </AdminLayout>

  <div
    v-if="notice"
    class="toast"
    :class="{ 'is-error': noticeError }"
    role="status"
    aria-live="polite"
  >
    {{ notice }}
  </div>
</template>

<style scoped>
.bootstrap-screen {
  display: grid;
  min-height: 100vh;
  min-height: 100svh;
  place-items: center;
  padding: 1.5rem;
}

.bootstrap-card {
  display: grid;
  justify-items: center;
  gap: 1rem;
  max-width: 420px;
  text-align: center;
}

.bootstrap-card h1 {
  margin: 0;
  font-size: 1.4rem;
  letter-spacing: -.025em;
}

.bootstrap-card p {
  margin: 0;
  color: #657e79;
  font-size: .9rem;
  line-height: 1.6;
}

.toast {
  position: fixed;
  right: 1.5rem;
  bottom: 1.5rem;
  z-index: 30;
  max-width: min(400px, calc(100vw - 3rem));
  padding: .85rem 1rem;
  border: 1px solid #b5d7cd;
  border-radius: 11px;
  background: #e8f6f0;
  box-shadow: 0 8px 28px rgb(14 60 51 / 12%);
  color: #276e5e;
  font-size: .85rem;
  line-height: 1.5;
}

.toast.is-error {
  border-color: #edcaca;
  background: #fff0ee;
  color: #a53b3b;
}
</style>
