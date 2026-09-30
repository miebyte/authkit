<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { getOverview } from '@/api/admin'
import { errorMessage } from '@/api/request'
import type { AdminOverview } from '@/types/admin'

const overview = ref<AdminOverview | null>(null)
const loading = ref(false)
const error = ref('')
let requestId = 0

const metrics = computed(() => [
  { label: '账号总数', value: overview.value?.accounts },
  { label: '邮箱绑定', value: overview.value?.email_bindings },
  { label: '微信绑定', value: overview.value?.wechat_bindings },
  { label: '有效会话', value: overview.value?.active_sessions },
])

function formatCount(value: number | undefined): string {
  return value === undefined ? '—' : new Intl.NumberFormat('zh-CN').format(value)
}

async function refresh(): Promise<void> {
  const current = ++requestId
  loading.value = true
  error.value = ''
  try {
    const result = await getOverview()
    if (current === requestId) overview.value = result
  } catch (cause: unknown) {
    if (current === requestId) error.value = errorMessage(cause)
  } finally {
    if (current === requestId) loading.value = false
  }
}

onMounted(refresh)
onBeforeUnmount(() => { requestId++ })
defineExpose({ refresh })
</script>

<template>
  <div class="overview-page">
    <header class="page-heading">
      <div>
        <p class="eyebrow">总览</p>
        <h1>身份数据概览</h1>
        <p class="page-description">查看账号、登录绑定与当前有效会话的规模。</p>
      </div>
      <span v-if="loading && overview" class="subtle-status" role="status">正在更新…</span>
    </header>

    <div v-if="error" class="state-message error-message" role="alert">
      <div>
        <strong>概览加载失败</strong>
        <p>{{ error }}</p>
      </div>
      <button class="button button-secondary" type="button" @click="refresh">重试</button>
    </div>

    <section class="metrics" aria-label="身份数据" :aria-busy="loading">
      <article v-for="metric in metrics" :key="metric.label" class="metric">
        <span>{{ metric.label }}</span>
        <strong>{{ formatCount(metric.value) }}</strong>
      </article>
    </section>

    <div class="next-step">
      <div>
        <strong>管理账号</strong>
        <p>查找账号并查看绑定与会话，按需撤销登录状态。</p>
      </div>
      <RouterLink class="button button-secondary" to="/accounts">前往账号管理</RouterLink>
    </div>
  </div>
</template>

<style scoped>
.overview-page {
  max-width: 1080px;
}

.page-heading {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 1.25rem;
  margin-bottom: 1.75rem;
}

.page-heading h1 {
  margin: 0;
  color: #193d39;
  font-size: clamp(1.7rem, 3vw, 2.2rem);
  line-height: 1.14;
  letter-spacing: -.035em;
}

.page-description {
  margin: .65rem 0 0;
  color: #718582;
  font-size: .9rem;
  line-height: 1.6;
}

.subtle-status {
  padding-bottom: .25rem;
  color: #607d78;
  font-size: .8rem;
  white-space: nowrap;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1rem;
}

.metric {
  display: flex;
  min-height: 154px;
  flex-direction: column;
  justify-content: space-between;
  padding: 1.4rem;
  border: 1px solid #e1eae6;
  border-radius: 16px;
  background: #fff;
  box-shadow: 0 6px 24px rgba(26, 64, 57, .035);
}

.metric span {
  color: #738a84;
  font-size: .85rem;
}

.metric strong {
  color: #193d39;
  font-size: clamp(1.9rem, 3vw, 2.5rem);
  font-variant-numeric: tabular-nums;
  font-weight: 690;
  line-height: 1;
  letter-spacing: -.045em;
}

.next-step {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.25rem;
  margin-top: 2.25rem;
  padding: 1.5rem;
  border: 1px solid #dbe8e3;
  border-radius: 16px;
  background: #eaf4ef;
}

.next-step strong {
  color: #234f46;
  font-size: .95rem;
}

.next-step p {
  margin: .3rem 0 0;
  color: #5e7b73;
  font-size: .85rem;
  line-height: 1.5;
}

@media (max-width: 1000px) {
  .metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 600px) {
  .page-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .metrics {
    gap: .7rem;
  }

  .metric {
    min-height: 124px;
    padding: 1.1rem;
  }

  .next-step {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
