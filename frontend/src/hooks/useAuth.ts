import { useSyncExternalStore } from 'react'
import { authStore } from '@/stores/authStore'

/** React hook to access auth state reactively. */
export function useAuth() {
  const state = useSyncExternalStore(
    authStore.subscribe,
    authStore.getState,
    authStore.getState,
  )

  return {
    user: state.user,
    isAuthenticated: state.accessToken !== null,
    login: authStore.login,
    logout: authStore.logout,
  }
}
