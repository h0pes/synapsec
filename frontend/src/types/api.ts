/** API response envelope matching backend ApiResponse<T>. */
export type ApiResponse<T> = {
  data: T | null
  error: ApiError | null
}

export type ApiError = {
  code: string
  message: string
}

/** Auth API types. */
export type LoginRequest = {
  username: string
  password: string
}

export type LoginResponse = {
  access_token: string
  refresh_token: string
  token_type: string
}

export type RefreshRequest = {
  refresh_token: string
}

export type UserResponse = {
  id: string
  username: string
  email: string
  display_name: string
  role: string
  is_active: boolean
  last_login: string | null
  created_at: string
}
