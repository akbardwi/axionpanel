// Route guard decisions. Production auth fails closed: anything that is not
// an authenticated session is treated as signed out.
export function resolveGuard({ path, status, designPreview = false }) {
  if (designPreview) return true
  const authenticated = status === 'authenticated'
  if (path === '/login') return authenticated ? '/overview' : true
  return authenticated ? true : '/login'
}
