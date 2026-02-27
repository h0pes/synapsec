import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'
import { Shield, Lock, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { authStore } from '@/stores/authStore'
import * as authApi from '@/api/auth'
import { ApiClientError } from '@/api/client'

export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)

    if (!username.trim()) {
      setError(t('auth.usernameRequired'))
      return
    }
    if (!password) {
      setError(t('auth.passwordRequired'))
      return
    }

    setLoading(true)
    try {
      const tokens = await authApi.login({ username, password })
      authStore.setTokens(tokens.access_token, tokens.refresh_token)
      const user = await authApi.getMe()
      authStore.setUser({
        id: user.id,
        username: user.username,
        displayName: user.display_name,
        role: user.role,
      })
      navigate({ to: '/' })
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message)
      } else {
        setError(t('auth.unexpectedError'))
      }
      authStore.logout()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen">
      {/* Brand panel — hidden on mobile */}
      <div className="relative hidden w-1/2 overflow-hidden bg-primary lg:block">
        {/* Subtle grid pattern overlay */}
        <div
          className="absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
          }}
        />
        {/* Gradient overlay for depth */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary via-primary to-primary/80" />

        {/* Brand content */}
        <div className="relative flex h-full flex-col items-center justify-center px-12 text-primary-foreground">
          <Shield className="mb-6 h-16 w-16 opacity-90" />
          <h1 className="mb-3 text-3xl font-bold tracking-tight">{t('app.title')}</h1>
          <p className="max-w-sm text-center text-base text-primary-foreground/70">
            {t('app.subtitle')}
          </p>
          {/* Decorative bottom line */}
          <div className="absolute bottom-8 h-px w-24 bg-primary-foreground/20" />
        </div>
      </div>

      {/* Form panel */}
      <div className="flex w-full items-center justify-center px-6 lg:w-1/2">
        <div className="w-full max-w-sm space-y-8">
          {/* Mobile brand (shown only below lg breakpoint) */}
          <div className="space-y-2 text-center lg:hidden">
            <Shield className="mx-auto h-10 w-10 text-primary" />
            <h1 className="text-2xl font-bold tracking-tight">{t('app.title')}</h1>
            <p className="text-sm text-muted-foreground">{t('app.subtitle')}</p>
          </div>

          {/* Desktop heading */}
          <div className="hidden space-y-2 lg:block">
            <h2 className="text-2xl font-bold tracking-tight">{t('auth.signIn')}</h2>
            <p className="text-sm text-muted-foreground">{t('auth.signInSubtitle')}</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="username">{t('auth.username')}</Label>
              <Input
                id="username"
                type="text"
                placeholder={t('auth.usernamePlaceholder')}
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={loading}
                className="h-11"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">{t('auth.password')}</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                className="h-11"
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                <Lock className="h-4 w-4 shrink-0" />
                {error}
              </div>
            )}

            <Button type="submit" className="h-11 w-full" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {t('common.loading')}
                </>
              ) : (
                t('auth.login')
              )}
            </Button>
          </form>

          {/* Footer */}
          <p className="text-center text-xs text-muted-foreground">
            {t('auth.secureLogin')}
          </p>
        </div>
      </div>
    </div>
  )
}
