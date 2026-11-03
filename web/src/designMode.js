// Design preview is an explicit, build-time switch only. The production app
// never falls back to a preview mode because of network or API failures.
export function designPreviewEnabled(env) {
  return env?.VITE_DESIGN_PREVIEW === 'true'
}

export function isDesignPreview() {
  return designPreviewEnabled(import.meta.env)
}
