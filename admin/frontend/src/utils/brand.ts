const configuredTitle = document.querySelector<HTMLMetaElement>('meta[name="authkit-title"]')?.content.trim()

export const brandTitle = configuredTitle || 'AuthKit'
