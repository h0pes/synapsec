import { apiGet, apiPost } from './client'
import type { LoginRequest, LoginResponse, UserResponse } from '@/types/api'

/** POST /auth/login — authenticate and receive tokens. */
export function login(credentials: LoginRequest): Promise<LoginResponse> {
  return apiPost<LoginResponse>('/auth/login', credentials)
}

/** POST /auth/refresh — refresh access token. */
export function refreshToken(refreshToken: string): Promise<LoginResponse> {
  return apiPost<LoginResponse>('/auth/refresh', {
    refresh_token: refreshToken,
  })
}

/** POST /auth/logout — invalidate current session. */
export function logout(): Promise<void> {
  return apiPost<void>('/auth/logout', {})
}

/** GET /auth/me — get current user info. */
export function getMe(): Promise<UserResponse> {
  return apiGet<UserResponse>('/auth/me')
}
