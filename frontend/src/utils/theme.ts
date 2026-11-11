/** 用户选择的主题模式与 ProLayout 实际应用的深浅色分开保存。 */
export type ThemeMode = 'auto' | 'light' | 'realDark';
export type ResolvedTheme = Exclude<ThemeMode, 'auto'>;

const THEME_MODE_KEY = 'ipban:theme-mode';
const SYSTEM_DARK_QUERY = '(prefers-color-scheme: dark)';

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'auto' || value === 'light' || value === 'realDark';
}

export function readThemeMode(): ThemeMode {
  try {
    const value = window.localStorage.getItem(THEME_MODE_KEY);
    return isThemeMode(value) ? value : 'light';
  } catch {
    return 'light';
  }
}

export function saveThemeMode(mode: ThemeMode): void {
  try {
    window.localStorage.setItem(THEME_MODE_KEY, mode);
  } catch {
    // 隐私模式或存储配额不足时保留当前会话中的选择。
  }
}

export function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'light';
  return window.matchMedia(SYSTEM_DARK_QUERY).matches ? 'realDark' : 'light';
}

export function resolveTheme(mode: ThemeMode): ResolvedTheme {
  return mode === 'auto' ? getSystemTheme() : mode;
}

export function subscribeSystemTheme(listener: (theme: ResolvedTheme) => void) {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    listener('light');
    return () => undefined;
  }
  const query = window.matchMedia(SYSTEM_DARK_QUERY);
  const onChange = (event: MediaQueryListEvent) => listener(event.matches ? 'realDark' : 'light');
  listener(query.matches ? 'realDark' : 'light');
  if (typeof query.addEventListener === 'function') {
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }
  query.addListener(onChange);
  return () => query.removeListener(onChange);
}
