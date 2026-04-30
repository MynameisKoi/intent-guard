import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/** Dev proxy replaces Create React App `setupProxy.js` — forwards /api → Flask. */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
});
