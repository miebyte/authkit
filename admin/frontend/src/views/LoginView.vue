<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { login, loginPassword, sendCode } from '@/api/admin'
import { errorMessage } from '@/api/request'
import { session } from '@/stores/session'
import { brandTitle } from '@/utils/brand'

const router = useRouter()
const route = useRoute()
const method = ref<'password' | 'email'>('password')
const identifier = ref('')
const password = ref('')
const email = ref('')
const code = ref('')
const form = ref<HTMLFormElement | null>(null)
const emailInput = ref<HTMLInputElement | null>(null)
const codeInput = ref<HTMLInputElement | null>(null)
const sending = ref(false)
const submitting = ref(false)
const feedback = ref('')
const feedbackError = ref(false)

function setFeedback(message: string, isError = false): void {
  feedback.value = message
  feedbackError.value = isError
}

function changeMethod(next: 'password' | 'email'): void {
  if (sending.value || submitting.value || method.value === next) return
  method.value = next
  password.value = ''
  code.value = ''
  setFeedback('')
}

async function handleSendCode(): Promise<void> {
  if (sending.value || submitting.value || !emailInput.value?.reportValidity()) return

  sending.value = true
  setFeedback('正在发送验证码…')
  try {
    await sendCode(email.value.trim())
    setFeedback('如果该邮箱是超管账号，请查收验证码。')
    codeInput.value?.focus()
  } catch (error) {
    setFeedback(errorMessage(error), true)
  } finally {
    sending.value = false
  }
}

async function handleLogin(): Promise<void> {
  if (sending.value || submitting.value || !form.value?.reportValidity()) {
    return
  }
  if (method.value === 'password' && Array.from(password.value).length > 128) {
    setFeedback('密码不能超过 128 个字符。', true)
    return
  }

  submitting.value = true
  setFeedback('正在登录…')
  try {
    const result = method.value === 'password'
      ? await loginPassword(identifier.value.trim(), password.value)
      : await login(email.value.trim(), code.value.trim())
    session.establish(result.token, result.account)
    code.value = ''
    password.value = ''
    const redirect = route.query.redirect
    await router.replace(redirect === '/accounts' || redirect === '/blacklist' ? redirect : '/overview')
  } catch (error) {
    setFeedback(errorMessage(error), true)
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <main class="login-screen">
    <section class="login-card" aria-labelledby="login-title">
      <div class="brand brand-login">
        <span class="brand-mark" aria-hidden="true">A</span>
        <span>{{ brandTitle }} <small>ADMIN</small></span>
      </div>

      <div class="login-heading">
        <p class="eyebrow">管理员入口</p>
        <h1 id="login-title">登录超管后台</h1>
        <p>使用管理员账号密码或邮箱验证码，访问账号与会话数据。</p>
      </div>

      <div class="login-methods" aria-label="登录方式">
        <button
          class="method-button"
          type="button"
          :aria-pressed="method === 'password'"
          :disabled="sending || submitting"
          @click="changeMethod('password')"
        >账号密码</button>
        <button
          class="method-button"
          type="button"
          :aria-pressed="method === 'email'"
          :disabled="sending || submitting"
          @click="changeMethod('email')"
        >邮箱验证码</button>
      </div>

      <form ref="form" @submit.prevent="handleLogin">
        <template v-if="method === 'password'">
          <label for="login-identifier">用户名或邮箱</label>
          <input
            id="login-identifier"
            v-model="identifier"
            class="first-field"
            name="username"
            type="text"
            autocomplete="username"
            placeholder="请输入管理员用户名或邮箱"
            required
          >
          <label for="login-password">密码</label>
          <input
            id="login-password"
            v-model="password"
            name="password"
            type="password"
            autocomplete="current-password"
            maxlength="256"
            placeholder="请输入密码"
            required
          >
        </template>

        <template v-else>
          <label for="login-email">邮箱地址</label>
          <div class="email-row">
            <input
              id="login-email"
              ref="emailInput"
              v-model="email"
              name="email"
              type="email"
              autocomplete="email"
              placeholder="请输入管理员邮箱"
              required
            >
            <button
              class="button button-secondary send-code"
              type="button"
              :disabled="sending || submitting"
              @click="handleSendCode"
            >
              {{ sending ? '正在发送…' : '发送验证码' }}
            </button>
          </div>

          <label for="login-code">验证码</label>
          <input
            id="login-code"
            ref="codeInput"
            v-model="code"
            name="code"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            pattern="[0-9]{6}"
            maxlength="6"
            placeholder="输入 6 位验证码"
            required
          >
        </template>

        <p class="form-feedback" :class="{ 'is-error': feedbackError }" role="status" aria-live="polite">
          {{ feedback }}
        </p>
        <button class="button button-primary login-submit" type="submit" :disabled="sending || submitting">
          {{ submitting ? '正在登录…' : '登录后台' }}
        </button>
      </form>

      <p class="login-footnote">仅授权的超管账号可访问后台数据</p>
    </section>
  </main>
</template>

<style scoped>
.login-screen {
  display: grid;
  min-height: 100vh;
  min-height: 100svh;
  place-items: center;
  padding: 32px 18px;
  background: radial-gradient(circle at 50% 15%, #e1efeb 0, transparent 42%), #f4f7f6;
}

.login-card {
  width: min(100%, 440px);
  padding: 35px;
  border: 1px solid #e1e8e6;
  border-radius: 18px;
  background: #fff;
  box-shadow: 0 24px 70px rgb(20 58 53 / 8%);
}

.brand-login {
  color: #193f3c;
}

.brand-login small {
  color: #5f8a85;
}

.login-heading {
  margin: 46px 0 31px;
}

.login-heading h1 {
  margin: 0 0 10px;
  font-size: 28px;
  line-height: 1.14;
  letter-spacing: -0.045em;
}

.login-heading > p:last-child {
  margin: 0;
  color: #708080;
  font-size: 14px;
  line-height: 1.7;
}

.login-card label {
  display: block;
  margin: 0 0 8px;
  color: #334b4b;
  font-size: 13px;
  font-weight: 650;
}

.login-card input {
  width: 100%;
  height: 44px;
  padding: 0 13px;
  border: 1px solid #d7e0df;
  border-radius: 9px;
  outline: 0;
  background: #fff;
  color: #203637;
  transition: border-color 150ms ease, box-shadow 150ms ease;
}

.login-card input:focus {
  border-color: #4b9d92;
  box-shadow: 0 0 0 3px rgb(49 139 126 / 14%);
}

.login-card input::placeholder {
  color: #9aabaa;
}

.login-methods {
  display: flex;
  gap: 6px;
  margin-bottom: 24px;
  padding: 4px;
  border-radius: 10px;
  background: #f1f5f4;
}

.method-button {
  min-height: 40px;
  flex: 1;
  padding: 8px;
  border: 0;
  border-radius: 7px;
  background: transparent;
  color: #708080;
  font: inherit;
  font-size: 13px;
  cursor: pointer;
}

.method-button[aria-pressed="true"] {
  background: #fff;
  color: #193f3c;
  box-shadow: 0 2px 6px rgb(20 58 53 / 7%);
}

.method-button:focus-visible {
  outline: 2px solid #4b9d92;
  outline-offset: 2px;
}

.method-button:disabled {
  cursor: default;
}

.first-field {
  margin-bottom: 23px;
}

.email-row {
  display: flex;
  gap: 8px;
  margin-bottom: 23px;
}

.email-row input {
  min-width: 0;
  flex: 1;
}

.send-code {
  min-height: 44px;
}

.form-feedback {
  min-height: 22px;
  margin: 8px 0 13px;
  color: #417b71;
  font-size: 12px;
  line-height: 1.5;
}

.form-feedback.is-error {
  color: #af4242;
}

.login-submit {
  width: 100%;
  min-height: 44px;
}

.login-footnote {
  margin: 25px 0 0;
  color: #98a5a4;
  font-size: 12px;
  text-align: center;
}

@media (max-width: 650px) {
  .login-card {
    padding: 28px 22px;
  }

  .email-row {
    flex-direction: column;
  }

  .send-code {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .login-card input {
    transition: none;
  }
}
</style>
