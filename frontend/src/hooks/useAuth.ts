import { useSyncExternalStore } from 'react'
import { authStore } from '@/stores/authStore'
import { logout as apiLogout } from '@/api/auth'

/** React hook to access auth state reactively. */
export function useAuth() {
  const state = useSyncExternalStore(
    authStore.subscribe,
    authStore.getState,
    authStore.getState,
  )

  const logout = () => {
    apiLogout()
    authStore.logout()
    window.location.href = '/login'
  }

  return {
    user: state.user,
    isAuthenticated: state.accessToken !== null,
    login: authStore.login,
    logout,
  }
}
