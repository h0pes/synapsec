/** Lightweight auth store using module-scoped state with subscribers. */

type AuthUser = {
  id: string
  username: string
  displayName: string
  role: string
}

type AuthState = {
  user: AuthUser | null
  accessToken: string | null
  refreshToken: string | null
}

type Listener = () => void

const STORAGE_KEY = 'synapsec_auth'

function loadFromStorage(): AuthState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw)
  } catch {
    // Corrupted storage — reset
  }
  return { user: null, accessToken: null, refreshToken: null }
}

let state: AuthState = loadFromStorage()
const listeners = new Set<Listener>()

function persist() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
}

function notify() {
  listeners.forEach((l) => l())
}

export const authStore = {
  getState: (): Readonly<AuthState> => state,

  isAuthenticated: () => state.accessToken !== null,

  getAccessToken: () => state.accessToken,

  setTokens(accessToken: string, refreshToken: string) {
    state = { ...state, accessToken, refreshToken }
    persist()
    notify()
  },

  setUser(user: AuthUser) {
    state = { ...state, user }
    persist()
    notify()
  },

  login(user: AuthUser, accessToken: string, refreshToken: string) {
    state = { user, accessToken, refreshToken }
    persist()
    notify()
  },

  logout() {
    state = { user: null, accessToken: null, refreshToken: null }
    localStorage.removeItem(STORAGE_KEY)
    notify()
  },

  subscribe(listener: Listener): () => void {
    listeners.add(listener)
    return () => listeners.delete(listener)
  },
}
