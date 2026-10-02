<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { addBlacklist, listBlacklist, removeBlacklist } from '@/api/admin'
import { errorMessage } from '@/api/request'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { session } from '@/stores/session'
import type { BlacklistEntry, BlacklistMethod } from '@/types/admin'
import { formatDate, shortId } from '@/utils/format'

const pageSize = 20
const method = ref<BlacklistMethod>('email')
const identifier = ref('')
const page = ref(1)
const total = ref(0)
const entries = ref<BlacklistEntry[]>([])
const loading = ref(false)
const listError = ref('')
const adding = ref(false)
const formError = ref('')
const successMessage = ref('')
const pendingEntry = ref<BlacklistEntry | null>(null)
const removing = ref(false)
const removeError = ref('')
const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))
const busy = computed(() => adding.value || removing.value)
const removeMessage = computed(() => {
  const entry = pendingEntry.value
  if (!entry) return ''
  const target = entry.method === 'wechat' ? `微信条目 ${shortId(entry.id)}` : entry.identifier
  return `确定解除“${target}”的黑名单限制吗？该凭证将不再受此条黑名单限制。`
})
const identifierLabel = computed(() => method.value === 'email'
  ? '邮箱地址'
  : method.value === 'password' ? '密码登录标识' : '微信 OpenID')
const identifierHint = computed(() => method.value === 'email'
  ? '邮箱会转换为小写并去除首尾空格。'
  : method.value === 'password'
    ? '输入密码登录标识，区分大小写并去除首尾空格。'
    : 'OpenID 区分大小写，不能包含空白字符；列表仅显示条目 ID。')
let listRequestId = 0

async function refresh(): Promise<void> {
  const current = ++listRequestId
  const token = session.token.value
  loading.value = true
  listError.value = ''
  entries.value = []
  try {
    const result = await listBlacklist(page.value, pageSize)
    if (current !== listRequestId || session.token.value !== token) return
    entries.value = result.items
    total.value = result.total
    page.value = result.page
  } catch (cause: unknown) {
    if (current === listRequestId && session.token.value === token) {
      listError.value = errorMessage(cause)
    }
  } finally {
    if (current === listRequestId) loading.value = false
  }
}

function changeMethod(): void {
  identifier.value = ''
  formError.value = ''
}

function changePage(next: number): void {
  if (loading.value || busy.value || next < 1 || next > pageCount.value) return
  page.value = next
  void refresh()
}

async function submit(): Promise<void> {
  if (busy.value) return
  const value = method.value === 'email'
    ? identifier.value.trim().toLowerCase()
    : method.value === 'password' ? identifier.value.trim() : identifier.value
  if (!value || method.value === 'wechat' && /\s/.test(value)) {
    formError.value = method.value === 'wechat' ? '请输入完整 OpenID，不能包含空白字符。' : `请输入${identifierLabel.value}。`
    return
  }
  const token = session.token.value
  adding.value = true
  formError.value = ''
  successMessage.value = ''
  try {
    await addBlacklist(method.value, value)
    if (session.token.value !== token) return
    identifier.value = ''
    successMessage.value = '已加入黑名单，该凭证及其关联账号无法登录或注册。'
    page.value = 1
    await refresh()
  } catch (cause: unknown) {
    if (session.token.value === token) formError.value = errorMessage(cause)
  } finally {
    adding.value = false
  }
}

function askRemove(entry: BlacklistEntry): void {
  if (busy.value) return
  pendingEntry.value = entry
  removeError.value = ''
  successMessage.value = ''
}

function cancelRemove(): void {
  if (removing.value) return
  pendingEntry.value = null
  removeError.value = ''
}

async function confirmRemove(): Promise<void> {
  const entry = pendingEntry.value
  if (!entry || busy.value) return
  const token = session.token.value
  removing.value = true
  removeError.value = ''
  try {
    await removeBlacklist(entry.id)
    if (session.token.value !== token) return
    pendingEntry.value = null
    successMessage.value = '黑名单限制已解除。'
    if (entries.value.length === 1 && page.value > 1) page.value--
    await refresh()
  } catch (cause: unknown) {
    if (session.token.value === token) removeError.value = errorMessage(cause)
  } finally {
    removing.value = false
  }
}

onMounted(refresh)
onBeforeUnmount(() => { listRequestId++ })
defineExpose({ refresh })
</script>

<template>
  <div class="blacklist-page">
    <header class="page-heading">
      <p class="eyebrow">黑名单</p>
      <h1>限制登录与注册</h1>
      <p>添加邮箱、密码登录标识或微信 OpenID，阻止该凭证及其关联账号继续使用。未注册的凭证也可添加。</p>
    </header>

    <div v-if="successMessage" class="status-message" role="status">{{ successMessage }}</div>

    <section class="panel add-panel" aria-labelledby="add-title">
      <h2 id="add-title">加入黑名单</h2>
      <form class="add-form" @submit.prevent="submit">
        <div class="method-field">
          <label for="blacklist-method">凭证类型</label>
          <select id="blacklist-method" v-model="method" :disabled="busy" @change="changeMethod">
            <option value="email">邮箱</option>
            <option value="wechat">微信 OpenID</option>
            <option value="password">密码登录标识</option>
          </select>
        </div>
        <div class="identifier-field">
          <label for="blacklist-identifier">{{ identifierLabel }}</label>
          <input
            id="blacklist-identifier"
            v-model="identifier"
            :type="method === 'email' ? 'email' : 'text'"
            :maxlength="method === 'email' ? 254 : 128"
            :placeholder="method === 'email' ? '例如 user@example.com' : method === 'password' ? '输入密码登录标识' : '输入原始 OpenID'"
            :disabled="busy"
            autocomplete="off"
            spellcheck="false"
            required
          >
        </div>
        <button class="button button-primary" type="submit" :disabled="busy">
          {{ adding ? '正在添加…' : '加入黑名单' }}
        </button>
      </form>
      <p class="form-hint">{{ identifierHint }}</p>
      <p v-if="formError" class="form-error" role="alert">{{ formError }}</p>
    </section>

    <section class="panel" aria-label="黑名单列表" :aria-busy="loading">
      <div class="table-toolbar">
        <span v-if="loading">正在加载黑名单…</span>
        <span v-else-if="listError">黑名单加载失败</span>
        <span v-else>共 {{ new Intl.NumberFormat('zh-CN').format(total) }} 条黑名单</span>
        <span>每页 {{ pageSize }} 条</span>
      </div>
      <p v-if="entries.length" class="table-hint">左右滑动查看完整表格与操作。</p>

      <div v-if="listError" class="error-state" role="alert">
        <p>{{ listError }}</p>
        <button class="button button-secondary" type="button" @click="refresh">重试</button>
      </div>
      <div v-else-if="loading" class="empty-state" role="status">正在加载黑名单…</div>
      <div v-else-if="!entries.length" class="empty-state">暂无黑名单。</div>
      <div v-else class="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">类型</th>
              <th scope="col">邮箱 / 密码登录标识 / 条目 ID</th>
              <th scope="col">加入时间</th>
              <th scope="col" class="action-cell">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="entry in entries" :key="entry.id">
              <td>{{ entry.method === 'email' ? '邮箱' : entry.method === 'password' ? '密码登录标识' : '微信' }}</td>
              <td>
                <span v-if="entry.method !== 'wechat'" class="identifier" :title="entry.identifier">{{ entry.identifier }}</span>
                <span v-else class="entry-id" :title="entry.id">{{ shortId(entry.id) }}</span>
              </td>
              <td class="date-cell">{{ formatDate(entry.created_at) }}</td>
              <td class="action-cell">
                <button
                  class="button button-secondary button-small"
                  type="button"
                  :disabled="busy"
                  @click="askRemove(entry)"
                >解除限制</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="pagination">
        <span>第 {{ page }} / {{ pageCount }} 页</span>
        <div>
          <button
            class="button button-secondary button-small"
            type="button"
            :disabled="loading || busy || !!listError || page <= 1"
            @click="changePage(page - 1)"
          >上一页</button>
          <button
            class="button button-secondary button-small"
            type="button"
            :disabled="loading || busy || !!listError || page >= pageCount"
            @click="changePage(page + 1)"
          >下一页</button>
        </div>
      </div>
    </section>

    <ConfirmDialog
      :open="pendingEntry !== null"
      title="解除黑名单限制"
      :message="removeMessage"
      confirm-label="解除限制"
      :busy="removing"
      :error="removeError"
      @cancel="cancelRemove"
      @confirm="confirmRemove"
    />
  </div>
</template>

<style scoped>
.blacklist-page { min-width: 0; }
.page-heading { margin-bottom: 1.5rem; }
.page-heading h1 {
  margin: 0;
  color: #193d39;
  font-size: clamp(1.7rem, 3vw, 2.2rem);
  line-height: 1.14;
  letter-spacing: -.035em;
}
.page-heading > p:last-child {
  margin: .65rem 0 0;
  color: var(--color-muted);
  font-size: .9rem;
  line-height: 1.6;
}
.status-message {
  margin-bottom: 1rem;
  padding: .8rem 1rem;
  border: 1px solid #b5d7cd;
  border-radius: 10px;
  background: #e8f6f0;
  color: #276e5e;
  font-size: .85rem;
}
.panel {
  overflow: hidden;
  border: 1px solid var(--color-line);
  border-radius: 15px;
  background: var(--color-surface);
  box-shadow: 0 6px 24px rgb(26 64 57 / 3.5%);
}
.add-panel {
  margin-bottom: 1.5rem;
  padding: 1.5rem;
}
.add-panel h2 {
  margin: 0 0 1rem;
  font-size: 1rem;
}
.add-form {
  display: flex;
  align-items: flex-end;
  gap: .6rem;
}
.add-form label {
  display: block;
  margin-bottom: .5rem;
  color: #334b4b;
  font-size: .8rem;
  font-weight: 650;
}
.method-field { flex: 0 0 145px; }
.identifier-field {
  min-width: 0;
  flex: 1;
}
.add-form input,
.add-form select {
  width: 100%;
  min-height: 44px;
  padding: 0 .8rem;
  border: 1px solid #d7e0df;
  border-radius: 9px;
  background: #fff;
  color: #203637;
  font: inherit;
  font-size: .85rem;
}
.add-form input:focus,
.add-form select:focus {
  outline: 0;
  border-color: #4b9d92;
  box-shadow: 0 0 0 3px rgb(49 139 126 / 14%);
}
.add-form .button { min-height: 44px; }
.form-hint {
  margin: .75rem 0 0;
  color: var(--color-muted);
  font-size: .75rem;
  line-height: 1.6;
}
.form-error {
  margin: .75rem 0 0;
  color: var(--color-danger);
  font-size: .8rem;
}
.table-toolbar {
  display: flex;
  justify-content: space-between;
  gap: .75rem;
  padding: 1rem 1.5rem;
  border-bottom: 1px solid #e8eeec;
  color: #79908d;
  font-size: .75rem;
}
.table-scroll {
  width: 100%;
  overflow-x: auto;
}
.table-hint {
  display: none;
}
table {
  width: 100%;
  min-width: 620px;
  border-collapse: collapse;
  text-align: left;
}
th {
  padding: .9rem 1.25rem;
  background: #fbfcfc;
  color: #829491;
  font-size: .7rem;
  font-weight: 650;
  white-space: nowrap;
}
td {
  padding: 1rem 1.25rem;
  border-top: 1px solid #edf1ef;
  color: #365150;
  font-size: .8rem;
  vertical-align: middle;
}
.identifier {
  display: block;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.entry-id {
  font: .75rem ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: nowrap;
}
.date-cell { white-space: nowrap; }
.action-cell { text-align: right; }
.empty-state {
  padding: 3.25rem 1rem;
  color: #7d918e;
  font-size: .8rem;
  text-align: center;
}
.error-state {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1.5rem;
  color: var(--color-danger);
  font-size: .85rem;
}
.pagination {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: .6rem;
  padding: .9rem 1.5rem;
  border-top: 1px solid #e8eeec;
  color: #738986;
  font-size: .75rem;
}
.pagination > div {
  display: flex;
  gap: .5rem;
}

@media (max-width: 650px) {
  .add-panel { padding: 1rem; }
  .add-form {
    align-items: stretch;
    flex-direction: column;
    gap: 1rem;
  }
  .method-field { flex-basis: auto; }
  .add-form .button { margin-top: .25rem; }
  .table-toolbar,
  .pagination { padding: .85rem 1rem; }
  .table-hint {
    display: block;
    margin: .8rem 1rem 0;
    color: var(--color-muted);
    font-size: .75rem;
  }
  .error-state {
    align-items: flex-start;
    flex-direction: column;
    padding: 1rem;
  }
  .button-small { min-height: 44px; }
}
</style>
