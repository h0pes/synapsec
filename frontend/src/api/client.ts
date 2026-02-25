import { authStore } from '@/stores/authStore'
import type { ApiResponse, RefreshRequest, LoginResponse } from '@/types/api'

const API_BASE = '/api/v1'

class ApiClientError extends Error {
  code: string
  status: number

  constructor(code: string, message: string, status: number) {
    super(message)
    this.name = 'ApiClientError'
    this.code = code
    this.status = status
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = authStore.getAccessToken()

  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  // Only set Content-Type for non-FormData bodies
  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  })

  // Handle 401 — attempt token refresh
  if (response.status === 401 && token) {
    const refreshed = await attemptRefresh()
    if (refreshed) {
      // Retry with new token
      headers['Authorization'] = `Bearer ${authStore.getAccessToken()}`
      const retryResponse = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers,
      })
      return parseResponse<T>(retryResponse)
    }
    // Refresh failed — force logout
    authStore.logout()
    window.location.href = '/login'
    throw new ApiClientError('UNAUTHORIZED', 'Session expired', 401)
  }

  return parseResponse<T>(response)
}

async function parseResponse<T>(response: Response): Promise<T> {
  const body: ApiResponse<T> = await response.json()

  if (body.error) {
    throw new ApiClientError(
      body.error.code,
      body.error.message,
      response.status,
    )
  }

  return body.data as T
}

async function attemptRefresh(): Promise<boolean> {
  const state = authStore.getState()
  if (!state.refreshToken) return false

  try {
    const body: RefreshRequest = { refresh_token: state.refreshToken }
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (!response.ok) return false

    const data: ApiResponse<LoginResponse> = await response.json()
    if (data.data) {
      authStore.setTokens(data.data.access_token, data.data.refresh_token)
      return true
    }
    return false
  } catch {
    return false
  }
}

/** GET request. */
export function apiGet<T>(
  path: string,
  params?: Record<string, string>,
): Promise<T> {
  const url = params
    ? `${path}?${new URLSearchParams(params).toString()}`
    : path
  return request<T>(url)
}

/** POST request with JSON body. */
export function apiPost<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: JSON.stringify(body),
  })
}

/** PUT request with JSON body. */
export function apiPut<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PUT',
    body: JSON.stringify(body),
  })
}

/** PATCH request with JSON body. */
export function apiPatch<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PATCH',
    body: JSON.stringify(body),
  })
}

/** DELETE request. */
export function apiDelete<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'DELETE' })
}

/** POST request with FormData (multipart upload). */
export function apiUpload<T>(path: string, formData: FormData): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: formData,
  })
}

export { ApiClientError }
