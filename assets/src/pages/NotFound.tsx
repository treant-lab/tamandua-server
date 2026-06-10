import { Head, Link } from '@inertiajs/react'
import { Home, Mail } from 'lucide-react'

interface NotFoundProps {
  status?: number
  message?: string
  path?: string
}

// Tamandua mascot SVG illustration (anteater shield logo)
function TamanduaMascot() {
  return (
    <div className="relative">
      {/* Glow effect behind the logo */}
      <div
        className="absolute inset-0 blur-3xl opacity-30"
        style={{ backgroundColor: 'var(--emerald-500)' }}
      />
      {/* Logo image */}
      <img
        src="/images/logo-lg.png"
        alt="Tamandua"
        className="relative h-32 w-auto object-contain"
        style={{
          filter: 'drop-shadow(0 0 20px var(--emerald-glow))',
        }}
      />
    </div>
  )
}

export default function NotFound({ status = 404, message, path }: NotFoundProps) {
  return (
    <>
      <Head title="404 - Page Not Found | Tamandua EDR" />

      <div
        className="min-h-screen flex items-center justify-center relative overflow-hidden"
        style={{ backgroundColor: 'var(--bg)' }}
      >
        {/* Grid pattern overlay */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `
              linear-gradient(to right, var(--hairline) 1px, transparent 1px),
              linear-gradient(to bottom, var(--hairline) 1px, transparent 1px)
            `,
            backgroundSize: '48px 48px',
            maskImage: 'radial-gradient(ellipse at center, black 0%, transparent 70%)',
            WebkitMaskImage: 'radial-gradient(ellipse at center, black 0%, transparent 70%)',
          }}
        />

        {/* Subtle radial gradient */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background: 'radial-gradient(circle at 50% 30%, var(--emerald-glow) 0%, transparent 50%)',
          }}
        />

        {/* Main content */}
        <div className="relative z-10 mx-auto flex max-w-2xl flex-col items-center justify-center px-6 py-16 text-center">
          {/* Tamandua mascot/logo */}
          <div className="mb-10">
            <TamanduaMascot />
          </div>

          {/* Large 404 display */}
          <h1
            className="text-[8rem] sm:text-[10rem] font-bold leading-none tracking-tighter"
            style={{
              color: 'var(--fg)',
              textShadow: '0 0 60px var(--emerald-glow)',
              fontFamily: 'var(--mono)',
            }}
          >
            {status}
          </h1>

          {/* Page not found heading */}
          <h2
            className="mt-4 text-2xl sm:text-3xl font-semibold"
            style={{ color: 'var(--fg)' }}
          >
            Page not found
          </h2>

          {/* Description */}
          <p
            className="mt-4 max-w-md text-base leading-relaxed"
            style={{ color: 'var(--muted)' }}
          >
            {message || "The page you're looking for doesn't exist or has been moved."}
          </p>

          {/* Show requested path if provided */}
          {path && (
            <p
              className="mt-4 max-w-full truncate rounded-md px-4 py-2 font-mono text-xs"
              style={{
                backgroundColor: 'var(--surface)',
                border: '1px solid var(--border)',
                color: 'var(--subtle)',
              }}
            >
              {path}
            </p>
          )}

          {/* Action buttons */}
          <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
            {/* Primary CTA - Go to Dashboard */}
            <Link
              href="/app/dashboard"
              className="inline-flex items-center gap-2 rounded-lg px-6 py-3 text-sm font-medium transition-all hover:opacity-90"
              style={{
                backgroundColor: 'var(--emerald-500)',
                color: 'white',
                boxShadow: '0 0 20px var(--emerald-glow)',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.boxShadow = '0 0 30px var(--emerald-glow)'
                e.currentTarget.style.backgroundColor = 'var(--emerald-400)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.boxShadow = '0 0 20px var(--emerald-glow)'
                e.currentTarget.style.backgroundColor = 'var(--emerald-500)'
              }}
            >
              <Home className="h-4 w-4" />
              Go to Dashboard
            </Link>

            {/* Secondary link - Contact support */}
            <a
              href="mailto:contato@treantlab.org"
              className="inline-flex items-center gap-2 text-sm font-medium transition-colors"
              style={{ color: 'var(--muted)' }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = 'var(--emerald-400)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--muted)'
              }}
            >
              <Mail className="h-4 w-4" />
              Contact support
            </a>
          </div>
        </div>
      </div>
    </>
  )
}
