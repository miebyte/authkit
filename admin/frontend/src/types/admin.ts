export interface AccountIdentity {
  id: string
  username: string
  email: string
}

export interface LoginResult {
  token: string
  account: AccountIdentity
}

export interface AdminOverview {
  accounts: number
  email_bindings: number
  wechat_bindings: number
  active_sessions: number
}

export interface AdminAccountSummary {
  id: string
  username: string
  email: string
  wechat: boolean
  active_sessions: number
}

export interface AdminAccountPage {
  items: AdminAccountSummary[]
  total: number
  page: number
  limit: number
}

export interface AdminBindingInfo {
  method: string
  identifier: string
}

export interface AdminSessionInfo {
  id: string
  expires: string
}

export interface AdminAccountDetail {
  id: string
  username: string
  email: string
  bindings: AdminBindingInfo[]
  sessions: AdminSessionInfo[]
}
