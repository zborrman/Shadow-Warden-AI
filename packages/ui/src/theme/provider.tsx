"use client";
import * as React from "react";

type Theme = "dark" | "light" | "system";

interface ThemeProviderState {
  theme:    Theme;
  setTheme: (theme: Theme) => void;
}

const ThemeProviderContext = React.createContext<ThemeProviderState>({
  theme:    "dark",
  setTheme: () => {},
});

interface ThemeProviderProps {
  children:     React.ReactNode;
  defaultTheme?: Theme;
  storageKey?:   string;
}

function ThemeProvider({
  children,
  defaultTheme = "dark",
  storageKey   = "sw-ui-theme",
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<Theme>(() => {
    if (typeof window !== "undefined") {
      return (localStorage.getItem(storageKey) as Theme) ?? defaultTheme;
    }
    return defaultTheme;
  });

  React.useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove("light", "dark");

    let effective: "light" | "dark" = theme === "system"
      ? window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
      : theme;

    root.classList.add(effective);
    root.setAttribute("data-theme", effective);
  }, [theme]);

  const setTheme = React.useCallback((t: Theme) => {
    localStorage.setItem(storageKey, t);
    setThemeState(t);
  }, [storageKey]);

  return (
    <ThemeProviderContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeProviderContext.Provider>
  );
}

function useTheme() {
  return React.useContext(ThemeProviderContext);
}

export { ThemeProvider, useTheme, type Theme };
