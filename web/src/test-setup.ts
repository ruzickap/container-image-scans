// Test setup (vite.config.ts "test.setupFiles"): DOM matchers like toBeInTheDocument()
import "@testing-library/jest-dom/vitest";

// jsdom has no ResizeObserver (bind:clientWidth of the charts)
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};
