<script setup>
import Home from "./views/Home.vue";
</script>

<template>
  <div class="app-shell">
    <header class="app-header">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">US</div>
        <div class="brand-copy">
          <h1>过河拆包</h1>
          <p>升级残留清理器</p>
        </div>
      </div>
      <span class="stage-badge">阶段 0 · 技术验证</span>
    </header>

    <main class="app-main">
      <Home />
    </main>
  </div>
</template>

<style lang="less">
@import (reference) "./styles/variables.less";

.app-shell {
  display: flex;
  flex-direction: column;
  min-height: 100%;
}

.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 20px;
  background: @surface;
  border-bottom: 1px solid @border;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.04em;
  color: #ffffff;
  background: @accent;
  border-radius: 9px;
}

.brand-copy {
  h1 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    letter-spacing: 0.02em;
  }

  p {
    margin: 0;
    font-size: 12px;
    color: @text-muted;
  }
}

.stage-badge {
  padding: 3px 10px;
  font-size: 12px;
  color: @text-muted;
  background: @neutral-soft;
  border-radius: 999px;
}

.app-main {
  width: 100%;
  max-width: 1080px;
  margin: 0 auto;
  padding: 20px;
}
</style>
