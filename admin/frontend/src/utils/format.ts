export interface NamedAccount {
  id: string
  username: string
  email: string
}

export function shortId(id: string): string {
  return id.length > 20 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id
}

export function accountName(account: NamedAccount): string {
  return account.username || account.email || shortId(account.id) || '未命名账号'
}

export function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? '未知'
    : new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
