<script setup>
import { computed } from "vue";

const props = defineProps({
  title: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    default: "idle",
  },
});

const STATUS_LABELS = {
  idle: "未运行",
  running: "运行中",
  passed: "通过",
  failed: "失败",
};

const label = computed(() => STATUS_LABELS[props.status] ?? "未知");
</script>

<template>
  <section class="status-card" :class="`is-${status}`">
    <header class="card-header">
      <h3>{{ title }}</h3>
      <span class="status-badge">{{ label }}</span>
    </header>

    <div class="card-body">
      <slot />
    </div>

    <footer v-if="$slots.actions" class="card-actions">
      <slot name="actions" />
    </footer>
  </section>
</template>

<style scoped lang="less">
@import (reference) "../../styles/variables.less";

.status-card {
  display: flex;
  flex-direction: column;
  min-width: 0;
  background: @surface;
  border: 1px solid @border;
  border-radius: @radius;
  box-shadow: @shadow;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 18px;
  border-bottom: 1px solid @border;

  h3 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
  }
}

.status-badge {
  flex: 0 0 auto;
  padding: 2px 9px;
  font-size: 12px;
  line-height: 18px;
  color: @text-muted;
  background: @neutral-soft;
  border-radius: 999px;
}

.is-running .status-badge {
  color: @accent;
  background: @accent-soft;
}

.is-passed .status-badge {
  color: @success;
  background: @success-soft;
}

.is-failed .status-badge {
  color: @danger;
  background: @danger-soft;
}

.card-body {
  flex: 1;
  min-height: 76px;
  padding: 16px 18px;
}

.card-actions {
  padding: 12px 18px;
  border-top: 1px solid @border;
  background: @surface-muted;
  border-radius: 0 0 @radius @radius;
}
</style>
