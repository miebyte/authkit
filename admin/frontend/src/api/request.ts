import { session } from '@/stores/session'
import { appBase } from '@/utils/base'

interface RequestOptions {
  method?: 'GET' | 'POST' | 'DELETE'
  body?: unknown
  auth?: boolean
}

const errorMessages: Record<string, string> = {
  forbidden: '没有权限执行此操作。',
  unauthorized: '登录已失效，请重新验证邮箱。',
  invalid_input: '输入内容有误，请检查后重试。',
  invalid_email: '邮箱地址格式不正确。',
  invalid_code: '验证码无效，请检查后重试。',
  challenge_mismatch: '验证码错误，请检查后重试。',
  challenge_invalid: '验证码已失效，请重新获取。',
  incorrect_code: '验证码错误，请检查后重试。',
  code_invalid: '验证码已失效，请重新获取。',
  resend_too_soon: '发送过于频繁，请稍后重试。',
  too_many_requests: '操作过于频繁，请稍后重试。',
  not_found: '请求的记录不存在或已被移除。',
  last_binding: '不能解除最后一种登录方式。',
  conflict: '当前状态不允许此操作，请刷新后重试。',
  mail_failed: '验证码邮件发送失败，请稍后重试。',
  internal: '服务器暂时无法处理请求，请稍后重试。',
}

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error && error.message
    ? error.message
    : '操作失败，请稍后重试。'
}

function responseError(data: unknown, status: number): ApiError {
  let code: unknown
  if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
    code = (data as Record<string, unknown>).error
  }
  let message = status === 401
    ? errorMessages.unauthorized
    : status === 403
      ? errorMessages.forbidden
      : `请求失败（${status}）`
  if (typeof code === 'string') {
    message = errorMessages[code]
      ?? (/^[a-z][a-z0-9_]*$/.test(code) ? message : code)
  }
  return new ApiError(message, status)
}

export async function request(path: string, options: RequestOptions = {}): Promise<unknown> {
  const auth = options.auth !== false
  const requestToken = auth ? session.token.value : ''
  const headers: Record<string, string> = {}
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (requestToken) headers.Authorization = `Bearer ${requestToken}`

  let response: Response
  try {
    response = await fetch(new URL(path, location.origin + appBase), {
      method: options.method ?? 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch {
    throw new Error('网络连接失败，请稍后重试。')
  }

  let data: unknown = null
  if (response.status !== 204) {
    try {
      data = await response.json() as unknown
    } catch {
      if (response.ok) throw new Error('服务器响应格式错误，请刷新后重试。')
    }
  }
  if (!response.ok) {
    if (auth && response.status === 401 && session.token.value === requestToken) {
      session.clear()
    }
    throw responseError(data, response.status)
  }
  return data
}
