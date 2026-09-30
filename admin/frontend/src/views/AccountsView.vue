<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import {
  deleteBinding,
  getAccount,
  listAccounts,
  revokeAllSessions,
  revokeSession,
} from '@/api/admin'
import { errorMessage } from '@/api/request'
import AccountDetailDialog from '@/components/accounts/AccountDetailDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { session } from '@/stores/session'
import type {
  AdminAccountDetail,
  AdminAccountSummary,
  AdminBindingInfo,
  AdminSessionInfo,
} from '@/types/admin'
import { accountName, shortId } from '@/utils/format'

interface PendingAction {
  title: string
  message: string
  label: string
  success: string
  accountId: string
  run: () => Promise<void>
}

const pageSize = 20
const draftQuery = ref('')
const query = ref('')
const page = ref(1)
const total = ref(0)
const accounts = ref<AdminAccountSummary[]>([])
const loading = ref(false)
const listError = ref('')
const selectedId = ref<string | null>(null)
const detailOpen = ref(false)
const detail = ref<AdminAccountDetail | null>(null)
const detailLoading = ref(false)
const detailError = ref('')
const pendingAction = ref<PendingAction | null>(null)
const actionBusy = ref(false)
const actionError = ref('')
const successMessage = ref('')
const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))
let listRequestId = 0
let detailRequestId = 0

async function loadAccounts(): Promise<void> {
  const current = ++listRequestId
  const token = session.token.value
  loading.value = true
  listError.value = ''
  accounts.value = []
  try {
    const result = await listAccounts(query.value, page.value, pageSize)
    if (current !== listRequestId || session.token.value !== token) return
    accounts.value = result.items
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

async function loadDetail(id: string): Promise<void> {
  const current = ++detailRequestId
  const token = session.token.value
  detail.value = null
  detailLoading.value = true
  detailError.value = ''
  try {
    const result = await getAccount(id)
    if (current === detailRequestId && selectedId.value === id && session.token.value === token) {
      detail.value = result
    }
  } catch (cause: unknown) {
    if (current === detailRequestId && selectedId.value === id && session.token.value === token) {
      detailError.value = errorMessage(cause)
    }
  } finally {
    if (current === detailRequestId) detailLoading.value = false
  }
}

async function refresh(): Promise<void> {
  const tasks: Promise<void>[] = [loadAccounts()]
  if (detailOpen.value && selectedId.value) tasks.push(loadDetail(selectedId.value))
  await Promise.all(tasks)
}

function applySearch(): void {
  query.value = draftQuery.value.trim()
  page.value = 1
  accounts.value = []
  successMessage.value = ''
  void loadAccounts()
}

function changePage(next: number): void {
  if (loading.value || next < 1 || next > pageCount.value) return
  page.value = next
  accounts.value = []
  void loadAccounts()
}

function openDetail(id: string): void {
  selectedId.value = id
  detailOpen.value = true
  void loadDetail(id)
}

function closeDetail(): void {
  detailOpen.value = false
  selectedId.value = null
  detail.value = null
  detailRequestId++
}

function retryDetail(): void {
  if (selectedId.value) void loadDetail(selectedId.value)
}

function askRevokeAll(account: AdminAccountSummary | AdminAccountDetail): void {
  successMessage.value = ''
  pendingAction.value = {
    title: '撤销全部会话',
    message: `确定撤销“${accountName(account)}”的全部有效会话吗？该账号需要重新登录。`,
    label: '全部撤销',
    success: '已撤销该账号的全部会话。',
    accountId: account.id,
    run: () => revokeAllSessions(account.id),
  }
  actionError.value = ''
}

function askRevokeSession(info: AdminSessionInfo): void {
  const account = detail.value
  if (!account) return
  successMessage.value = ''
  pendingAction.value = {
    title: '撤销会话',
    message: `确定撤销“${accountName(account)}”的会话 ${shortId(info.id)} 吗？`,
    label: '撤销会话',
    success: '会话已撤销。',
    accountId: account.id,
    run: () => revokeSession(account.id, info.id),
  }
  actionError.value = ''
}

function askDeleteBinding(binding: AdminBindingInfo): void {
  const account = detail.value
  if (!account) return
  successMessage.value = ''
  const type = binding.method === 'wechat' ? '微信' : binding.method === 'email' ? '邮箱' : binding.method
  pendingAction.value = {
    title: '解除登录绑定',
    message: `确定解除“${accountName(account)}”的${type}绑定吗？这会移除对应登录方式。`,
    label: '解除绑定',
    success: '登录绑定已解除。',
    accountId: account.id,
    run: () => deleteBinding(account.id, binding.method),
  }
  actionError.value = ''
}

function cancelAction(): void {
  if (actionBusy.value) return
  pendingAction.value = null
  actionError.value = ''
}

async function confirmAction(): Promise<void> {
  const action = pendingAction.value
  if (!action || actionBusy.value) return
  actionBusy.value = true
  actionError.value = ''
  try {
    await action.run()
    pendingAction.value = null
    successMessage.value = action.success
    await refresh()
  } catch (cause: unknown) {
    actionError.value = errorMessage(cause)
  } finally {
    actionBusy.value = false
  }
}

onMounted(loadAccounts)
onBeforeUnmount(() => {
  listRequestId++
  detailRequestId++
})
defineExpose({ refresh })
</script>

<template>
  <div class="accounts-page">
    <header class="page-heading">
      <div>
        <p class="eyebrow">账号管理</p>
        <h1>查找与管理账号</h1>
        <p>查看登录绑定与有效会话，按需撤销登录状态。</p>
      </div>
    </header>

    <div v-if="successMessage" class="status-message" role="status">
      {{ successMessage }}
    </div>

    <section class="panel" aria-label="账号列表" :aria-busy="loading">
      <form class="search-form" role="search" @submit.prevent="applySearch">
        <label for="account-query">搜索账号</label>
        <div class="search-controls">
          <input
            id="account-query"
            v-model="draftQuery"
            type="search"
            placeholder="搜索账号 ID、用户名或邮箱"
            autocomplete="off"
          >
          <button class="button button-primary" type="submit">查询</button>
        </div>
      </form>

      <div class="table-toolbar">
        <span v-if="loading">正在加载账号…</span>
        <span v-else-if="listError">账号加载失败</span>
        <span v-else>共 {{ new Intl.NumberFormat('zh-CN').format(total) }} 个账号</span>
        <span class="page-size">每页 {{ pageSize }} 条</span>
        <span class="table-hint">左右滑动查看完整表格</span>
      </div>

      <div v-if="listError" class="state-message error-message" role="alert">
        <div>
          <strong>账号加载失败</strong>
          <p>{{ listError }}</p>
        </div>
        <button class="button button-secondary" type="button" @click="loadAccounts">重试</button>
      </div>

      <div v-if="accounts.length" class="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">账号</th>
              <th scope="col">邮箱</th>
              <th scope="col">微信</th>
              <th scope="col">有效会话</th>
              <th scope="col" class="action-heading">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="account in accounts" :key="account.id">
              <td>
                <span class="account-name" :title="accountName(account)">
                  {{ accountName(account) }}
                </span>
                <span class="account-id">{{ shortId(account.id) }}</span>
              </td>
              <td :class="{ muted: !account.email }">{{ account.email || '未绑定' }}</td>
              <td>
                <span class="status-pill" :class="{ off: !account.wechat }">
                  {{ account.wechat ? '已绑定' : '未绑定' }}
                </span>
              </td>
              <td class="count">{{ account.active_sessions }}</td>
              <td>
                <div class="row-actions">
                  <button
                    class="button button-secondary button-small"
                    type="button"
                    @click="openDetail(account.id)"
                  >查看详情</button>
                  <button
                    class="button button-outline-danger button-small"
                    type="button"
                    :disabled="account.active_sessions === 0"
                    @click="askRevokeAll(account)"
                  >撤销会话</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="!loading && !listError" class="empty-state">
        {{ query ? '没有找到匹配的账号。' : '暂无账号。' }}
      </div>
      <div v-else-if="loading && !listError && !accounts.length" class="empty-state" role="status">
        正在加载账号…
      </div>

      <div class="pagination">
        <span>第 {{ page }} / {{ pageCount }} 页</span>
        <div>
          <button
            class="button button-secondary button-small"
            type="button"
            :disabled="loading || !!listError || page <= 1"
            @click="changePage(page - 1)"
          >上一页</button>
          <button
            class="button button-secondary button-small"
            type="button"
            :disabled="loading || !!listError || page >= pageCount"
            @click="changePage(page + 1)"
          >下一页</button>
        </div>
      </div>
    </section>

    <AccountDetailDialog
      :open="detailOpen"
      :account="detail"
      :loading="detailLoading"
      :error="detailError"
      :admin-id="session.account.value?.id ?? ''"
      :busy="actionBusy"
      @close="closeDetail"
      @retry="retryDetail"
      @delete-binding="askDeleteBinding"
      @revoke-session="askRevokeSession"
      @revoke-all="detail && askRevokeAll(detail)"
    />

    <ConfirmDialog
      :open="pendingAction !== null"
      :title="pendingAction?.title ?? ''"
      :message="pendingAction?.message ?? ''"
      :confirm-label="pendingAction?.label ?? ''"
      :busy="actionBusy"
      :error="actionError"
      @cancel="cancelAction"
      @confirm="confirmAction"
    />
  </div>
</template>

<style scoped>
.accounts-page {
  min-width: 0;
}

.page-heading {
  margin-bottom: 1.5rem;
}

.page-heading h1 {
  margin: 0;
  color: #193d39;
  font-size: clamp(1.7rem, 3vw, 2.2rem);
  line-height: 1.14;
  letter-spacing: -.035em;
}

.page-heading > div > p:last-child {
  margin: .65rem 0 0;
  color: #718582;
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
  border: 1px solid #e0e8e5;
  border-radius: 15px;
  background: #fff;
  box-shadow: 0 6px 24px rgb(26 64 57 / 3.5%);
}

.search-form {
  padding: 1.5rem;
}

.search-form label {
  display: block;
  margin-bottom: .5rem;
  color: #334b4b;
  font-size: .8rem;
  font-weight: 650;
}

.search-controls {
  display: flex;
  max-width: 560px;
  gap: .55rem;
}

.search-controls input {
  width: 100%;
  min-width: 0;
  min-height: 44px;
  flex: 1;
  padding: 0 .8rem;
  border: 1px solid #d7e0df;
  border-radius: 9px;
  outline: 0;
  color: #203637;
}

.search-controls input:focus {
  border-color: #4b9d92;
  box-shadow: 0 0 0 3px rgb(49 139 126 / 14%);
}

.search-controls input::placeholder {
  color: #9aabaa;
}

.table-toolbar {
  display: flex;
  justify-content: space-between;
  gap: .75rem;
  padding: .9rem 1.5rem;
  border-top: 1px solid #e8eeec;
  border-bottom: 1px solid #e8eeec;
  color: #79908d;
  font-size: .75rem;
}

.table-hint {
  display: none;
}

.table-scroll {
  width: 100%;
  overflow-x: auto;
}

table {
  width: 100%;
  min-width: 800px;
  border-collapse: collapse;
  text-align: left;
}

th:first-child,
td:first-child {
  min-width: 155px;
}

th:last-child,
td:last-child {
  min-width: 215px;
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

tbody tr:hover {
  background: #fcfefd;
}

.account-name {
  display: block;
  max-width: 170px;
  overflow: hidden;
  color: #1e3d3b;
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.account-id {
  display: block;
  margin-top: .3rem;
  color: #96a5a2;
  font: .7rem ui-monospace, SFMono-Regular, Menlo, monospace;
  white-space: nowrap;
}

.muted {
  color: #9aaba8;
}

.status-pill {
  display: inline-flex;
  padding: .3rem .55rem;
  border-radius: 6px;
  background: #e9f5f0;
  color: #287766;
  font-size: .7rem;
  font-weight: 700;
  white-space: nowrap;
}

.status-pill.off {
  background: #f2f4f3;
  color: #82918d;
}

.count {
  font-variant-numeric: tabular-nums;
}

.action-heading {
  text-align: right;
}

.row-actions {
  display: flex;
  justify-content: flex-end;
  gap: .45rem;
}

.empty-state {
  padding: 3.25rem 1rem;
  color: #7d918e;
  font-size: .8rem;
  text-align: center;
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

@media (max-width: 1100px) {
  .page-size {
    display: none;
  }

  .table-hint {
    display: inline;
  }
}

@media (max-width: 650px) {
  .search-form {
    padding: 1rem;
  }

  .table-toolbar,
  .pagination {
    padding: .85rem 1rem;
  }

}
</style>
