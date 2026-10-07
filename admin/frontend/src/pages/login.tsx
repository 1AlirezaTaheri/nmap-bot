import * as React from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useNavigate } from 'react-router-dom'
import { Activity, Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { z } from 'zod'
import { api, ApiError, type CaptchaChallenge } from '@/lib/api'
import { Button, Input, Label, FieldError } from '@/components/ui'
import { Spinner } from '@/components/feedback'

const schema = z.object({
  username: z.string().min(1, 'Username is required').max(64, 'Username is too long'),
  password: z.string().min(1, 'Password is required'),
  captchaAnswer: z.string().optional(),
})

type FormValues = z.infer<typeof schema>

export function LoginPage(): JSX.Element {
  const navigate = useNavigate()
  const [showPassword, setShowPassword] = React.useState(false)
  const [serverError, setServerError] = React.useState<string | null>(null)
  const [shake, setShake] = React.useState(false)
  const [challenge, setChallenge] = React.useState<CaptchaChallenge | null>(null)
  const [challengeError, setChallengeError] = React.useState<string | null>(null)

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { username: '', password: '', captchaAnswer: '' },
  })

  /**
   * Fetch a challenge and remember it.
   *
   * Deliberately unconditional. Whether the server enforces a CAPTCHA is not
   * discoverable without trying to log in, so the field stays hidden until a
   * failed attempt proves one is needed. Asking the server first would mean
   * either showing a field it ignores or omitting one it requires.
   */
  const loadChallenge = React.useCallback(async (signal?: AbortSignal) => {
    setChallengeError(null)
    try {
      setChallenge(await api.captcha(signal))
      setValue('captchaAnswer', '')
    } catch (error) {
      // Most often a 429 from the shared rate limiter. Worth surfacing: the
      // login that follows would be refused for the same reason.
      setChallenge(null)
      setChallengeError(
        error instanceof ApiError ? error.message : 'Could not load the security question.',
      )
    }
  }, [setValue])

  React.useEffect(() => {
    const controller = new AbortController()
    void loadChallenge(controller.signal)
    // The abort on unmount matters: without it a response that lands after
    // navigation would set state on a page that is no longer mounted.
    return () => controller.abort()
  }, [loadChallenge])

  /**
   * Autofill and password managers can populate an input without emitting the
   * React `onChange` react-hook-form subscribes to, which leaves the form state
   * empty while the fields look filled. Re-read the live DOM values right before
   * validation so we validate what the user actually sees.
   */
  function syncVisibleValues(): void {
    const username = document.getElementById('username')
    const password = document.getElementById('password')
    const captchaAnswer = document.getElementById('captcha-answer')
    if (username instanceof HTMLInputElement) setValue('username', username.value)
    if (password instanceof HTMLInputElement) setValue('password', password.value)
    if (captchaAnswer instanceof HTMLInputElement)
      setValue('captchaAnswer', captchaAnswer.value)
  }

  async function onSubmit(values: FormValues): Promise<void> {
    setServerError(null)
    const answer = (values.captchaAnswer ?? '').trim()
    // Send the challenge only when one is showing, and only with a non-empty
    // answer. An empty answer would arrive as a present-but-wrong challenge,
    // which is a different error from "no challenge supplied".
    const captcha =
      challenge && answer !== '' ? { token: challenge.token, answer } : undefined

    try {
      await api.login(values.username, values.password, captcha)
      // Full navigation so the shell re-mounts with a fresh session.
      navigate('/', { replace: true })
    } catch (error) {
      const message =
        error instanceof ApiError ? error.message : 'Sign-in failed. Please try again.'
      setServerError(message)
      setShake(true)
      window.setTimeout(() => setShake(false), 450)

      // A challenge is single-use server-side, so this one cannot be retried.
      // Fetch a replacement whether or not the server asked for one: after a
      // wrong password the old challenge is also gone, and leaving it in place
      // would cost the user a second attempt they cannot see the cause of.
      void loadChallenge()
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-bg px-4 py-10">
      {/* Subtle green-tinted gradient wash; pointer-events-none so it can
          never swallow a click on the form. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-70"
        style={{
          background:
            'radial-gradient(60rem 40rem at 15% 10%, rgb(var(--primary) / 0.16), transparent 60%),' +
            'radial-gradient(50rem 35rem at 85% 90%, rgb(var(--info) / 0.14), transparent 60%)',
        }}
      />

      <div className={shake ? 'relative w-full max-w-sm animate-shake' : 'relative w-full max-w-sm'}>
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-primary shadow-lg shadow-primary/25">
            <Activity className="h-6 w-6 text-primary-fg" />
          </div>
          <h1 className="text-xl font-semibold text-fg">NetSentinel</h1>
          <p className="mt-1 text-sm text-muted">Network intelligence &amp; security monitoring</p>
        </div>

        <form
          onSubmit={(event) => {
            syncVisibleValues()
            void handleSubmit(onSubmit)(event)
          }}
          className="card space-y-4 bg-surface/70 p-6 backdrop-blur-xl"
          noValidate
        >
          {serverError ? (
            <div className="flex items-start gap-2 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{serverError}</span>
            </div>
          ) : null}

          {challengeError ? (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning-soft px-3 py-2 text-sm text-warning">
              <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{challengeError}</span>
            </div>
          ) : null}

          <div>
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              autoComplete="username"
              autoFocus
              placeholder="admin"
              aria-invalid={Boolean(errors.username)}
              {...register('username')}
            />
            <FieldError>{errors.username?.message}</FieldError>
          </div>

          <div>
            <Label htmlFor="password">Password</Label>
            <div className="relative">
              <Input
                id="password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                placeholder="••••••••••••"
                className="pr-10"
                aria-invalid={Boolean(errors.password)}
                {...register('password')}
              />
              <button
                type="button"
                className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted transition-colors hover:text-fg"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <FieldError>{errors.password?.message}</FieldError>
          </div>

          {challenge ? (
            <div>
              <Label htmlFor="captcha-answer">Security question</Label>
              <div className="flex items-stretch gap-2">
                <span
                  className="flex select-none items-center rounded-md border border-border bg-muted/40 px-3 font-mono text-sm text-fg"
                  aria-hidden
                >
                  {challenge.question}
                </span>
                <Input
                  id="captcha-answer"
                  inputMode="numeric"
                  autoComplete="off"
                  placeholder="Answer"
                  aria-invalid={Boolean(errors.captchaAnswer)}
                  {...register('captchaAnswer')}
                />
              </div>
              <FieldError>{errors.captchaAnswer?.message}</FieldError>
            </div>
          ) : null}

          <Button type="submit" className="w-full" disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <Spinner />
                Signing in…
              </>
            ) : (
              'Sign in'
            )}
          </Button>
        </form>

        <p className="mt-4 text-center text-xs text-muted">
          Sessions use an HttpOnly cookie. Five failed attempts per minute are throttled and audited.
        </p>
      </div>
    </div>
  )
}