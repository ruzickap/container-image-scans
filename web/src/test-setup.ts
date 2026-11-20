// Test setup (vite.config.ts "test.setupFiles"): DOM matchers like toBeInTheDocument()
import "@testing-library/jest-dom/vitest";

// jsdom has no layout engine - the CVE list scrolls into view after a click
Element.prototype.scrollIntoView = () => {};
