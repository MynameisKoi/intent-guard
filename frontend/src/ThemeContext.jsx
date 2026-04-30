import { createContext, useContext, useEffect, useState } from "react";

const ThemeContext = createContext(null);

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(() => {
    const t = localStorage.getItem("intentguard-frontend-theme");
    return t === "light" ? "light" : "dark";
  });

  useEffect(() => {
    document.documentElement.classList.toggle("theme-light", theme === "light");
    localStorage.setItem("intentguard-frontend-theme", theme);
  }, [theme]);

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return ctx;
}
