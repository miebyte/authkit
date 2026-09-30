<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import type { AccountIdentity } from '@/types/admin'
import { brandTitle } from '@/utils/brand'

const props = defineProps<{
  account: AccountIdentity
  refreshing: boolean
  loggingOut: boolean
}>()

const emit = defineEmits<{
  refresh: []
  logout: []
}>()

const adminName = computed(() =>
  props.account.email || props.account.username || props.account.id || '管理员',
)
</script>

<template>
  <div class="admin-layout">
    <aside class="sidebar" aria-label="后台导航">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">A</span>
        <span>{{ brandTitle }} <small>ADMIN</small></span>
      </div>

      <nav class="side-nav" aria-label="页面">
        <RouterLink class="nav-link" active-class="is-active" to="/overview">概览</RouterLink>
        <RouterLink class="nav-link" active-class="is-active" to="/accounts">账号管理</RouterLink>
        <RouterLink class="nav-link" active-class="is-active" to="/blacklist">黑名单</RouterLink>
      </nav>

      <div class="sidebar-account">
        <span class="sidebar-account-label">当前管理员</span>
        <strong>{{ adminName }}</strong>
      </div>
    </aside>

    <div class="main-area">
      <header class="topbar">
        <div class="topbar-title"><span class="topbar-dot" aria-hidden="true"></span>超管后台</div>
        <div class="topbar-actions">
          <button
            class="button button-quiet"
            type="button"
            :disabled="refreshing || loggingOut"
            @click="emit('refresh')"
          >
            {{ refreshing ? '正在刷新…' : '刷新数据' }}
          </button>
          <button
            class="button button-quiet"
            type="button"
            :disabled="loggingOut"
            @click="emit('logout')"
          >
            {{ loggingOut ? '正在退出…' : '退出登录' }}
          </button>
        </div>
      </header>

      <main class="content">
        <slot />
      </main>
    </div>
  </div>
</template>

<style scoped>
.admin-layout {
  display: flex;
  min-height: 100vh;
  min-height: 100svh;
}

.sidebar {
  position: sticky;
  top: 0;
  display: flex;
  height: 100vh;
  height: 100svh;
  flex: 0 0 226px;
  flex-direction: column;
  padding: 27px 17px;
  background: #193c3b;
}

.sidebar .brand {
  padding: 0 9px;
}

.side-nav {
  display: grid;
  gap: 5px;
  margin-top: 54px;
}

.nav-link {
  display: flex;
  min-height: 44px;
  align-items: center;
  padding: 0 14px;
  border-radius: 9px;
  color: #aac2bf;
  font-size: 13px;
  font-weight: 600;
  transition: background-color 150ms ease, color 150ms ease;
}

.nav-link:hover,
.nav-link.is-active {
  background: #28514e;
  color: #fff;
}

.nav-link:active {
  background: #32605b;
}

.sidebar-account {
  display: grid;
  gap: 7px;
  margin-top: auto;
  padding: 18px 11px 4px;
  border-top: 1px solid rgb(255 255 255 / 12%);
  overflow-wrap: anywhere;
}

.sidebar-account-label {
  color: #93b0ad;
  font-size: 11px;
}

.sidebar-account strong {
  color: #e5f2f0;
  font-size: 13px;
  font-weight: 600;
}

.main-area {
  min-width: 0;
  flex: 1;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 5;
  display: flex;
  min-height: 68px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 0 44px;
  background: rgb(255 255 255 / 88%);
  border-bottom: 1px solid #e3e9e7;
  backdrop-filter: blur(18px) saturate(140%);
}

.topbar-title {
  display: flex;
  align-items: center;
  gap: 9px;
  color: #436361;
  font-size: 13px;
  font-weight: 700;
  white-space: nowrap;
}

.topbar-dot {
  width: 7px;
  height: 7px;
  flex: 0 0 7px;
  border-radius: 50%;
  background: #3da890;
}

.topbar-actions {
  display: flex;
  align-items: center;
  gap: 7px;
}

.content {
  width: min(100%, 1240px);
  margin: 0 auto;
  padding: 46px 44px 80px;
}

@media (max-width: 900px) {
  .sidebar {
    flex-basis: 190px;
  }

  .topbar {
    padding: 0 25px;
  }

  .content {
    padding: 35px 25px 70px;
  }
}

@media (max-width: 650px) {
  .admin-layout {
    display: block;
  }

  .sidebar {
    position: sticky;
    z-index: 6;
    width: 100%;
    height: auto;
    padding: 12px 18px 8px;
  }

  .sidebar .brand {
    padding: 0;
  }

  .side-nav {
    display: flex;
    gap: 6px;
    margin-top: 8px;
  }

  .nav-link {
    min-height: 44px;
    padding: 0 11px;
  }

  .sidebar-account {
    display: none;
  }

  .topbar {
    position: static;
    min-height: 54px;
    padding: 0 15px;
  }

  .topbar-actions {
    gap: 0;
  }

  .topbar-actions .button {
    min-height: 44px;
    padding: 0 10px;
  }

  .content {
    padding: 27px 15px 55px;
  }
}

@media (prefers-reduced-transparency: reduce) {
  .topbar {
    background: #fff;
    backdrop-filter: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .nav-link {
    transition: none;
  }
}

@media (prefers-contrast: more) {
  .nav-link.is-active {
    outline: 2px solid #fff;
    outline-offset: -2px;
  }
}
</style>
