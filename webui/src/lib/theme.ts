import { useCallback, useEffect, useState } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "headless_theme";

export function readTheme(): Theme {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    /* localStorage 不可用时回落到系统偏好 */
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
}

export function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* 忽略持久化失败 */
  }
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(readTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === "dark" ? "light" : "dark";
      persistTheme(next);
      return next;
    });
  }, []);

  return { theme, toggle };
}
