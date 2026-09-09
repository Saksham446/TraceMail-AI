import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

const AUTH_API_URL = 'http://localhost:5001/api/auth'

function Login() {

  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleLogin = async (event) => {

    event.preventDefault()

    setError('')

    if (!email.trim() || !password) {
      setError('Please enter your email and password.')
      return
    }

    try {

      setLoading(true)

      const response = await fetch(`${AUTH_API_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim(),
          password,
        }),
      })

      const data = await response.json()

      if (!response.ok || !data.success) {
        throw new Error(
          data.message || 'Login failed.'
        )
      }

      localStorage.setItem(
        'tracemail_auth_token',
        data.token
      )

      localStorage.setItem(
        'tracemail_user',
        JSON.stringify(data.user)
      )

      navigate('/')

    } catch (err) {

      console.error('Login error:', err)

      setError(
        err.message || 'Unable to connect to authentication service.'
      )

    } finally {

      setLoading(false)

    }
  }


  return (

    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-6">

      <div className="w-full max-w-md">

        {/* Logo */}

        <div className="mb-8 text-center">

          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/10 text-3xl">
            🛡️
          </div>

          <h1 className="mt-4 text-2xl font-bold text-cyan-400">
            TraceMail AI
          </h1>

          <p className="mt-2 text-sm text-slate-500">
            Email Forensics Platform
          </p>

        </div>


        {/* Login Card */}

        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">

          <div className="mb-6">

            <p className="text-xs font-medium uppercase tracking-wider text-cyan-500">
              Secure Access
            </p>

            <h2 className="mt-2 text-xl font-semibold text-slate-100">
              Sign in to TraceMail AI
            </h2>

            <p className="mt-2 text-sm leading-6 text-slate-500">
              Access the email threat detection and forensic
              intelligence platform.
            </p>

          </div>


          {/* Error */}

          {error && (

            <div className="mb-5 rounded-lg border border-red-500/20 bg-red-500/5 p-3">

              <p className="text-sm text-red-400">
                {error}
              </p>

            </div>

          )}


          <form
            onSubmit={handleLogin}
            className="space-y-5"
          >

            {/* Email */}

            <div>

              <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">
                Email
              </label>

              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="admin@tracemail.ai"
                autoComplete="email"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-500"
              />

            </div>


            {/* Password */}

            <div>

              <label className="mb-2 block text-xs font-medium uppercase tracking-wider text-slate-500">
                Password
              </label>

              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                autoComplete="current-password"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-500"
              />

            </div>


            {/* Submit */}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-lg bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
            >

              {loading
                ? 'Signing in...'
                : 'Sign In →'}

            </button>

          </form>


          {/* Demo Access */}

          <div className="mt-6 border-t border-slate-800 pt-5">

            <p className="text-center text-[10px] uppercase tracking-wider text-slate-600">
              SIH Demo Access
            </p>

            <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950 p-3">

              <p className="text-xs text-slate-500">
                Admin account
              </p>

              <p className="mt-1 text-xs text-slate-300">
                admin@tracemail.ai
              </p>

            </div>

          </div>

        </div>


        {/* Footer */}

        <p className="mt-6 text-center text-xs text-slate-600">
          TraceMail AI • Secure Investigation Platform
        </p>

      </div>

    </div>

  )
}

export default Login