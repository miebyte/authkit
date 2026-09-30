<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'

const props = defineProps<{
  open: boolean
  title: string
  message: string
  confirmLabel: string
  busy: boolean
  error: string
}>()

const emit = defineEmits<{
  cancel: []
  confirm: []
}>()

const dialog = ref<HTMLDialogElement | null>(null)

function syncOpen(): void {
  const element = dialog.value
  if (!element) return
  if (props.open && !element.open) element.showModal()
  if (!props.open && element.open) element.close()
}

function handleCancel(event: Event): void {
  event.preventDefault()
  if (!props.busy) emit('cancel')
}

function handleClose(): void {
  if (props.open && !props.busy) emit('cancel')
}

onMounted(syncOpen)
watch(() => props.open, syncOpen, { flush: 'post' })
</script>

<template>
  <dialog
    ref="dialog"
    class="confirm-dialog"
    role="alertdialog"
    aria-labelledby="confirm-title"
    aria-describedby="confirm-message"
    @cancel="handleCancel"
    @close="handleClose"
  >
    <div class="confirm-icon" aria-hidden="true">!</div>
    <h2 id="confirm-title">{{ title }}</h2>
    <p id="confirm-message" class="confirm-message">{{ message }}</p>
    <p v-if="error" class="confirm-error" role="alert">{{ error }}</p>
    <div class="confirm-actions">
      <button class="button button-secondary" type="button" :disabled="busy" @click="emit('cancel')">
        取消
      </button>
      <button class="button button-danger" type="button" :disabled="busy" @click="emit('confirm')">
        {{ busy ? '正在处理…' : confirmLabel }}
      </button>
    </div>
  </dialog>
</template>

<style scoped>
.confirm-dialog {
  width: min(calc(100% - 32px), 390px);
  max-width: none;
  max-height: calc(100dvh - 32px);
  padding: 27px;
  overflow-y: auto;
  border: 0;
  border-radius: 15px;
  background: #fff;
  box-shadow: 0 24px 80px rgb(10 41 38 / 22%);
}

.confirm-dialog::backdrop {
  background: rgb(13 37 35 / 42%);
}

.confirm-icon {
  display: grid;
  width: 36px;
  height: 36px;
  place-items: center;
  border-radius: 9px;
  background: #fcebea;
  color: #aa4242;
  font-weight: 800;
}

.confirm-dialog h2 {
  margin: 19px 0 8px;
  color: #1d3031;
  font-size: 19px;
  line-height: 1.25;
}

.confirm-message {
  margin: 0;
  color: #69807b;
  font-size: 13px;
  line-height: 1.7;
  overflow-wrap: anywhere;
}

.confirm-error {
  margin: 16px 0 0;
  padding: 10px 12px;
  border-radius: 8px;
  background: #fff0ee;
  color: #a53b3b;
  font-size: 12px;
  line-height: 1.5;
}

.confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 25px;
}

@media (max-width: 650px) {
  .confirm-dialog {
    padding: 24px;
  }

  .confirm-actions .button {
    min-height: 44px;
  }
}

@media (prefers-contrast: more) {
  .confirm-error {
    border: 1px solid #a53b3b;
  }
}
</style>
