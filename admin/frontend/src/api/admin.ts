import { request } from '@/api/request'
import type {
  AccountIdentity,
  AdminAccountDetail,
  AdminAccountPage,
  AdminAccountSummary,
  AdminBindingInfo,
  AdminOverview,
  AdminSessionInfo,
  BlacklistEntry,
  BlacklistMethod,
  BlacklistPage,
  LoginResult,
} from '@/types/admin'

function invalidResponse(): never {
  throw new Error('服务器响应格式错误，请刷新后重试。')
}

function asRecord(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return invalidResponse()
  }
  return value as Record<string, unknown>
}

function asString(value: unknown): string {
  if (typeof value !== 'string') return invalidResponse()
  return value
}

function asID(value: unknown): string {
  const id = asString(value)
  if (!id) return invalidResponse()
  return id
}

function asCount(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    return invalidResponse()
  }
  return value
}

function asPositiveInt(value: unknown): number {
  const number = asCount(value)
  if (number === 0) return invalidResponse()
  return number
}

function asArray(value: unknown): unknown[] {
  if (value === null) return []
  if (!Array.isArray(value)) return invalidResponse()
  return value
}

function parseIdentity(value: unknown): AccountIdentity {
  const data = asRecord(value)
  return {
    id: asID(data.id),
    username: asString(data.username),
    email: asString(data.email),
  }
}

function parseOverview(value: unknown): AdminOverview {
  const data = asRecord(value)
  return {
    accounts: asCount(data.accounts),
    email_bindings: asCount(data.email_bindings),
    wechat_bindings: asCount(data.wechat_bindings),
    active_sessions: asCount(data.active_sessions),
  }
}

function parseSummary(value: unknown): AdminAccountSummary {
  const data = asRecord(value)
  if (typeof data.wechat !== 'boolean' || typeof data.password !== 'boolean') return invalidResponse()
  return {
    id: asID(data.id),
    username: asString(data.username),
    email: asString(data.email),
    wechat: data.wechat,
    password: data.password,
    active_sessions: asCount(data.active_sessions),
  }
}

function parsePage(value: unknown): AdminAccountPage {
  const data = asRecord(value)
  return {
    items: asArray(data.items).map(parseSummary),
    total: asCount(data.total),
    page: asPositiveInt(data.page),
    limit: asPositiveInt(data.limit),
  }
}

function parseBinding(value: unknown): AdminBindingInfo {
  const data = asRecord(value)
  return {
    method: asString(data.method),
    identifier: asString(data.identifier),
  }
}

function parseSession(value: unknown): AdminSessionInfo {
  const data = asRecord(value)
  const expires = asString(data.expires)
  if (Number.isNaN(Date.parse(expires))) return invalidResponse()
  return { id: asID(data.id), expires }
}

function parseDetail(value: unknown): AdminAccountDetail {
  const data = asRecord(value)
  return {
    id: asID(data.id),
    username: asString(data.username),
    email: asString(data.email),
    bindings: asArray(data.bindings).map(parseBinding),
    sessions: asArray(data.sessions).map(parseSession),
  }
}

function parseBlacklistEntry(value: unknown): BlacklistEntry {
  const data = asRecord(value)
  if (data.method !== 'email' && data.method !== 'wechat' && data.method !== 'password') return invalidResponse()
  const createdAt = asString(data.created_at)
  if (Number.isNaN(Date.parse(createdAt))) return invalidResponse()
  return {
    id: asID(data.id),
    method: data.method,
    identifier: asString(data.identifier),
    created_at: createdAt,
  }
}

export async function listBlacklist(page: number, limit = 20): Promise<BlacklistPage> {
  const params = new URLSearchParams({ page: String(page), limit: String(limit) })
  const data = asRecord(await request(`api/blacklist?${params}`))
  return {
    items: asArray(data.items).map(parseBlacklistEntry),
    total: asCount(data.total),
    page: asPositiveInt(data.page),
    limit: asPositiveInt(data.limit),
  }
}

export async function addBlacklist(method: BlacklistMethod, identifier: string): Promise<void> {
  await request('api/blacklist', { method: 'POST', body: { method, identifier } })
}

export async function removeBlacklist(id: string): Promise<void> {
  await request(`api/blacklist/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function getMe(): Promise<AccountIdentity> {
  return parseIdentity(await request('api/me'))
}

export async function sendCode(email: string): Promise<void> {
  await request('api/codes', { method: 'POST', body: { email }, auth: false })
}

export async function login(email: string, code: string): Promise<LoginResult> {
  const data = asRecord(await request('api/login', {
    method: 'POST',
    body: { email, code },
    auth: false,
  }))
  return { token: asID(data.token), account: parseIdentity(data.account) }
}

export async function loginPassword(identifier: string, password: string): Promise<LoginResult> {
  const data = asRecord(await request('api/password/login', {
    method: 'POST',
    body: { identifier, password },
    auth: false,
  }))
  return { token: asID(data.token), account: parseIdentity(data.account) }
}

export async function logout(): Promise<void> {
  await request('api/logout', { method: 'POST' })
}

export async function getOverview(): Promise<AdminOverview> {
  return parseOverview(await request('api/overview'))
}

export async function listAccounts(
  query: string,
  page: number,
  limit = 20,
): Promise<AdminAccountPage> {
  const params = new URLSearchParams({ query, page: String(page), limit: String(limit) })
  return parsePage(await request(`api/accounts?${params}`))
}

export async function getAccount(id: string): Promise<AdminAccountDetail> {
  return parseDetail(await request(`api/accounts/${encodeURIComponent(id)}`))
}

export async function deleteBinding(accountId: string, method: string): Promise<void> {
  await request(`api/accounts/${encodeURIComponent(accountId)}/bindings/${encodeURIComponent(method)}`, {
    method: 'DELETE',
  })
}

export async function revokeSession(accountId: string, sessionId: string): Promise<void> {
  await request(`api/accounts/${encodeURIComponent(accountId)}/sessions/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
  })
}

export async function revokeAllSessions(accountId: string): Promise<void> {
  await request(`api/accounts/${encodeURIComponent(accountId)}/sessions/revoke`, {
    method: 'POST',
  })
}
