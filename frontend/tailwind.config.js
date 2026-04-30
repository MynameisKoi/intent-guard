/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        "ig-bg": "#0c0f14",
        "ig-panel": "#12161e",
        "ig-border": "#1e2533",
        "ig-muted": "#8b95a8",
        "ig-accent": "#34d399",
        "ig-danger": "#f87171",
        "ig-warn": "#fb923c",
      },
    },
  },
  plugins: [],
};
