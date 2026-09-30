const pagePaths = new Set(['login', 'overview', 'accounts'])

export function resolveAppBase(pathname: string): string {
  const segments = pathname.split('/').filter(Boolean)
  if (pagePaths.has(segments[segments.length - 1] ?? '')) {
    segments.pop()
  }
  return `/${segments.length ? `${segments.join('/')}/` : ''}`
}

function bundleBase(): string | null {
  const moduleURL = new URL(import.meta.url)
  if (moduleURL.origin !== location.origin) return null
  return moduleURL.pathname.match(/^(.*\/)assets\/[^/]+\.js$/)?.[1] ?? null
}

export const appBase = bundleBase() ?? resolveAppBase(location.pathname)
