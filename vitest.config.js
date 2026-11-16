import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // 当前 Vite 8.3.8 + Vitest 4.1.12 组合下，从 "vitest" 显式导入
    // describe/it/expect 会在 worker 中触发运行时错误；使用官方 globals 注入。
    globals: true,
    include: ["src/**/*.test.js"],
  },
});
