<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import type {
  AdminAccountDetail,
  AdminBindingInfo,
  AdminSessionInfo,
} from '@/types/admin'
import { accountName, formatDate, shortId } from '@/utils/format'

const props = defineProps<{
  open: boolean
  account: AdminAccountDetail | null
  loading: boolean
  error: string
  adminId: string
  busy: boolean
}>()

const emit = defineEmits<{
  close: []
  retry: []
  deleteBinding: [binding: AdminBindingInfo]
  revokeSession: [session: AdminSessionInfo]
  revokeAll: []
}>()

const dialog = ref<HTMLDialogElement | null>(null)
const detailTitle = computed(() => props.account ? accountName(props.account) : '账号详情')
const isOwnBinding = computed(() => !!props.adminId && props.account?.id === props.adminId)
const isLastBinding = computed(() => props.account?.bindings.length === 1)

function bindingName(method: string): string {
  if (method === 'wechat') return '微信'
  if (method === 'email') return '邮箱'
  return method || '其他方式'
}

function bindingDescription(binding: AdminBindingInfo): string {
  return binding.method === 'wechat' ? '已绑定' : binding.identifier || '已绑定'
}

function syncOpen(): void {
  const element = dialog.value
  if (!element) return
  if (props.open && !element.open) element.showModal()
  if (!props.open && element.open) element.close()
}

function handleClose(): void {
  if (props.open) emit('close')
}

onMounted(syncOpen)
watch(() => props.open, syncOpen, { flush: 'post' })
</script>

<template>
  <dialog ref="dialog" class="detail-dialog" aria-labelledby="detail-title" @close="handleClose">
    <div class="detail-shell">
      <header class="detail-header">
        <div>
          <p class="eyebrow">账号详情</p>
          <h2 id="detail-title">{{ detailTitle }}</h2>
        </div>
        <button class="close-button" type="button" aria-label="关闭账号详情" @click="emit('close')">
          <span aria-hidden="true">×</span>
        </button>
      </header>

      <div class="detail-content">
        <p v-if="loading" class="detail-message" role="status">正在加载账号详情…</p>

        <div v-else-if="error" class="detail-error" role="alert">
          <p>加载失败：{{ error }}</p>
          <button class="button button-secondary" type="button" @click="emit('retry')">重试</button>
        </div>

        <template v-else-if="account">
          <div class="detail-meta">
            <div class="detail-meta-row"><span>账号 ID</span><strong>{{ account.id }}</strong></div>
            <div class="detail-meta-row"><span>用户名</span><strong>{{ account.username || '未设置' }}</strong></div>
            <div class="detail-meta-row"><span>邮箱</span><strong>{{ account.email || '未绑定' }}</strong></div>
          </div>

          <section class="detail-section" aria-labelledby="bindings-title">
            <h3 id="bindings-title">登录绑定</h3>
            <p v-if="account.bindings.length === 0" class="detail-empty">暂无绑定信息。</p>
            <div v-for="binding in account.bindings" :key="binding.method" class="detail-item">
              <div class="detail-item-main">
                <strong>{{ bindingName(binding.method) }}</strong>
                <small>{{ bindingDescription(binding) }}</small>
                <small v-if="isOwnBinding || isLastBinding" class="detail-reason">
                  {{ isOwnBinding ? '超管自己的绑定不可解除' : '最后一种登录方式不可解除' }}
                </small>
              </div>
              <button
                class="button button-small button-outline-danger"
                type="button"
                :disabled="busy || isOwnBinding || isLastBinding"
                @click="emit('deleteBinding', binding)"
              >
                解除绑定
              </button>
            </div>
          </section>

          <section class="detail-section" aria-labelledby="sessions-title">
            <h3 id="sessions-title">有效会话</h3>
            <p v-if="account.sessions.length === 0" class="detail-empty">暂无有效会话。</p>
            <div v-for="session in account.sessions" :key="session.id" class="detail-item">
              <div class="detail-item-main">
                <strong>会话 {{ shortId(session.id) }}</strong>
                <small>到期时间：{{ formatDate(session.expires) }}</small>
              </div>
              <button
                class="button button-small button-outline-danger"
                type="button"
                :disabled="busy"
                @click="emit('revokeSession', session)"
              >
                撤销
              </button>
            </div>
          </section>

          <section class="detail-footer" aria-labelledby="revoke-all-title">
            <h3 id="revoke-all-title">撤销全部会话</h3>
            <p>让这个账号的所有有效会话立即失效，用户需要重新登录。</p>
            <button
              class="button button-small button-outline-danger"
              type="button"
              :disabled="busy || account.sessions.length === 0"
              @click="emit('revokeAll')"
            >
              撤销全部会话
            </button>
          </section>
        </template>

        <div v-else class="detail-error" role="status">
          <p>账号详情暂不可用。</p>
          <button class="button button-secondary" type="button" @click="emit('retry')">重试</button>
        </div>
      </div>
    </div>
  </dialog>
</template>

<style scoped>
.detail-dialog {
  position: fixed;
  inset: 0 0 0 auto;
  width: min(100%, 520px);
  max-width: none;
  height: 100vh;
  height: 100dvh;
  max-height: none;
  margin: 0;
  padding: 0;
  border: 0;
  border-radius: 16px 0 0 16px;
  background: #fff;
  box-shadow: 0 24px 80px rgb(10 41 38 / 22%);
}

.detail-dialog::backdrop {
  background: rgb(13 37 35 / 42%);
}

.detail-shell {
  display: flex;
  height: 100%;
  flex-direction: column;
}

.detail-header {
  display: flex;
  flex: 0 0 auto;
  align-items: flex-start;
  justify-content: space-between;
  gap: 15px;
  padding: 28px 29px 22px;
  border-bottom: 1px solid #e6ecea;
}

.detail-header h2 {
  margin: 0;
  font-size: 23px;
  line-height: 1.2;
  letter-spacing: -0.04em;
  overflow-wrap: anywhere;
}

.close-button {
  display: grid;
  width: 44px;
  height: 44px;
  flex: 0 0 44px;
  place-items: center;
  border: 0;
  border-radius: 9px;
  background: #f0f4f3;
  color: #58716f;
  font-size: 26px;
  line-height: 1;
}

.close-button:hover {
  background: #e3ece9;
}

.close-button:active {
  background: #d6e4e0;
}

.detail-content {
  min-height: 0;
  flex: 1;
  overflow-y: auto;
  padding: 27px 29px 35px;
  overscroll-behavior: contain;
}

.detail-meta {
  display: grid;
  gap: 14px;
  padding: 18px;
  border: 1px solid #e3eae8;
  border-radius: 11px;
  background: #fbfcfc;
}

.detail-meta-row {
  display: grid;
  grid-template-columns: 95px minmax(0, 1fr);
  gap: 10px;
  font-size: 12px;
}

.detail-meta-row span {
  color: #859995;
}

.detail-meta-row strong {
  color: #304e4a;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.detail-section {
  margin-top: 32px;
}

.detail-section h3,
.detail-footer h3 {
  margin: 0 0 13px;
  color: #2a4744;
  font-size: 13px;
}

.detail-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 15px 0;
  border-bottom: 1px solid #eaf0ed;
}

.detail-item-main {
  min-width: 0;
}

.detail-item-main strong {
  display: block;
  color: #294743;
  font-size: 13px;
}

.detail-item-main small {
  display: block;
  margin-top: 5px;
  color: #8a9d99;
  font-size: 11px;
  overflow-wrap: anywhere;
}

.detail-item-main .detail-reason {
  color: #ac6660;
}

.detail-empty {
  padding: 19px;
  border: 1px dashed #dce7e3;
  border-radius: 10px;
  color: #90a19e;
  font-size: 12px;
}

.detail-footer {
  margin-top: 35px;
  padding-top: 25px;
  border-top: 1px solid #e5ece9;
}

.detail-footer h3 {
  margin-bottom: 7px;
}

.detail-footer p {
  margin: 0 0 16px;
  color: #849792;
  font-size: 12px;
  line-height: 1.6;
}

.detail-message,
.detail-error {
  color: #829592;
  font-size: 13px;
  line-height: 1.6;
}

.detail-error p {
  margin: 0 0 16px;
}

@media (max-width: 650px) {
  .detail-dialog {
    border-radius: 0;
  }

  .detail-header {
    padding: 22px 20px 17px;
  }

  .detail-content {
    padding: 22px 20px 30px;
  }

  .detail-item {
    align-items: flex-start;
  }

  .detail-item .button {
    min-height: 44px;
  }
}

@media (prefers-contrast: more) {
  .detail-meta,
  .detail-empty {
    border-color: #68817c;
  }
}
</style>
