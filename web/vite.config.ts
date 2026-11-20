/// <reference types="vitest/config" />
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { svelteTesting } from "@testing-library/svelte/vite";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
  // Relative asset paths - the site is served from /container-image-scans/ on GitHub Pages
  base: "./",
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: "jsdom",
    // Bun runtime can not start the default "forks" pool (child process IPC) - worker threads work
    pool: "threads",
    setupFiles: ["./src/test-setup.ts"],
  },
});
