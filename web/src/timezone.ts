export const DEFAULT_TIME_ZONE = 'Asia/Shanghai'

export function resolveTimeZone(timeZone?: string) {
  const zone = timeZone?.trim() || DEFAULT_TIME_ZONE
  try {
    Intl.DateTimeFormat('en-US', { timeZone: zone }).format(new Date())
    return zone
  } catch {
    return DEFAULT_TIME_ZONE
  }
}
