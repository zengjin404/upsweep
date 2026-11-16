<script setup>
import { onMounted, reactive, ref } from "vue";

import StatusCard from "../components/common/StatusCard.vue";
import {
  getAppInfo,
  probeWindowsApi,
  runDatabaseCheck,
} from "../services/diagnostics";
import { formatBytes } from "../utils/format";

const environment = reactive({ state: "idle", error: "", data: null });
const database = reactive({ state: "idle", error: "", data: null });
const windows = reactive({ state: "idle", error: "", data: null });
const runningAll = ref(false);

function errorMessage(error) {
  if (!error) {
    return "未知错误";
  }
  if (typeof error === "string") {
    return error;
  }
  if (typeof error.message === "string" && error.message) {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

async function runEnvironment() {
  environment.state = "running";
  environment.error = "";
  environment.data = null;

  try {
    environment.data = await getAppInfo();
    environment.state = "passed";
  } catch (error) {
    environment.state = "failed";
    environment.error = errorMessage(error);
  }
}

async function runDatabase() {
  database.state = "running";
  database.error = "";
  database.data = null;

  try {
    const report = await runDatabaseCheck();
    database.data = report;
    if (report.ok) {
      database.state = "passed";
    } else {
      database.state = "failed";
      database.error = "SQLite 自检返回失败状态。";
    }
  } catch (error) {
    database.state = "failed";
    database.error = errorMessage(error);
  }
}

async function runWindows() {
  windows.state = "running";
  windows.error = "";
  windows.data = null;

  try {
    const report = await probeWindowsApi();
    windows.data = report;
    if (report.ok) {
      windows.state = "passed";
    } else {
      windows.state = "failed";
      windows.error = "存在未通过的 Windows API 检查，详见下方结果。";
    }
  } catch (error) {
    windows.state = "failed";
    windows.error = errorMessage(error);
  }
}

async function runAll() {
  runningAll.value = true;
  try {
    await Promise.all([runEnvironment(), runDatabase(), runWindows()]);
  } finally {
    runningAll.value = false;
  }
}

onMounted(runEnvironment);
</script>

<template>
  <div class="home">
    <section class="hero">
      <div class="hero-copy">
        <h2>技术验证</h2>
        <p>
          验证桌面窗口、前后端通信、SQLite 基本读写与 Windows API 调用。
          本页不会扫描或修改任何软件目录。
        </p>
      </div>
      <button class="button primary" :disabled="runningAll" @click="runAll">
        {{ runningAll ? "正在运行…" : "运行全部检查" }}
      </button>
    </section>

    <div class="card-grid">
      <StatusCard
        class="span-all"
        title="应用运行时与前后端通信"
        :status="environment.state"
      >
        <template #actions>
          <button
            class="button"
            :disabled="environment.state === 'running'"
            @click="runEnvironment"
          >
            重新检测
          </button>
        </template>

        <p v-if="environment.state === 'idle'" class="muted">尚未运行。</p>
        <p
          v-else-if="environment.state === 'failed' && environment.error"
          class="error-text"
        >
          {{ environment.error }}
        </p>
        <dl v-if="environment.data" class="kv">
          <div>
            <dt>产品名称</dt>
            <dd>{{ environment.data.productName }}</dd>
          </div>
          <div>
            <dt>包名</dt>
            <dd>{{ environment.data.packageName }}</dd>
          </div>
          <div>
            <dt>版本</dt>
            <dd>{{ environment.data.version }}</dd>
          </div>
          <div>
            <dt>应用标识</dt>
            <dd>{{ environment.data.identifier }}</dd>
          </div>
          <div>
            <dt>构建模式</dt>
            <dd>{{ environment.data.buildProfile }}</dd>
          </div>
          <div class="wide">
            <dt>应用数据目录</dt>
            <dd class="path">{{ environment.data.dataDir }}</dd>
          </div>
        </dl>
      </StatusCard>

      <StatusCard title="SQLite 基本读写" :status="database.state">
        <template #actions>
          <button
            class="button"
            :disabled="database.state === 'running'"
            @click="runDatabase"
          >
            运行数据库自检
          </button>
        </template>

        <p v-if="database.state === 'idle'" class="muted">
          尚未运行。自检会执行真实事务，但不会遗留测试数据。
        </p>
        <p v-if="database.error" class="error-text">{{ database.error }}</p>
        <dl v-if="database.data" class="kv compact">
          <div>
            <dt>SQLite 引擎</dt>
            <dd>{{ database.data.engineVersion }}</dd>
          </div>
          <div>
            <dt>结构版本</dt>
            <dd>v{{ database.data.schemaVersion }}</dd>
          </div>
          <div>
            <dt>写入 / 读回 / 删除</dt>
            <dd>{{ database.data.roundtripOk ? "通过" : "失败" }}</dd>
          </div>
          <div>
            <dt>文件大小</dt>
            <dd>{{ formatBytes(database.data.databaseSizeBytes) }}</dd>
          </div>
          <div>
            <dt>耗时</dt>
            <dd>{{ database.data.elapsedMs }} ms</dd>
          </div>
          <div class="wide">
            <dt>数据库路径</dt>
            <dd class="path">{{ database.data.databasePath ?? "内存数据库" }}</dd>
          </div>
        </dl>
      </StatusCard>

      <StatusCard title="Windows API 调用" :status="windows.state">
        <template #actions>
          <button
            class="button"
            :disabled="windows.state === 'running'"
            @click="runWindows"
          >
            运行 API 探测
          </button>
        </template>

        <p v-if="windows.state === 'idle'" class="muted">
          尚未运行。仅执行只读探测，不写入或删除任何文件。
        </p>
        <p v-if="windows.error" class="error-text">{{ windows.error }}</p>

        <template v-if="windows.data">
          <ul class="check-list">
            <li
              v-for="check in windows.data.checks"
              :key="check.name"
              :class="check.passed ? 'ok' : 'bad'"
            >
              <span class="dot" aria-hidden="true"></span>
              <div class="check-copy">
                <strong>{{ check.name }}</strong>
                <p>{{ check.detail }}</p>
              </div>
              <span class="check-state">
                {{ check.passed ? "通过" : "失败" }}
              </span>
            </li>
          </ul>

          <dl class="kv compact">
            <div>
              <dt>Windows 目录</dt>
              <dd class="path">{{ windows.data.windowsDirectory ?? "—" }}</dd>
            </div>
            <div>
              <dt>System32 目录</dt>
              <dd class="path">{{ windows.data.systemDirectory ?? "—" }}</dd>
            </div>
            <div>
              <dt>属性探测文件</dt>
              <dd class="path">{{ windows.data.probeFile ?? "—" }}</dd>
            </div>
          </dl>
        </template>
      </StatusCard>
    </div>
  </div>
</template>

<style scoped lang="less">
@import (reference) "../styles/variables.less";

.home {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.hero {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 18px 20px;
  background: @surface;
  border: 1px solid @border;
  border-radius: @radius;
  box-shadow: @shadow;

  h2 {
    margin: 0 0 4px;
    font-size: 17px;
    font-weight: 600;
  }

  p {
    margin: 0;
    color: @text-muted;
  }
}

.hero-copy {
  min-width: 0;
}

.card-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.span-all {
  grid-column: 1 / -1;
}

.button {
  flex: 0 0 auto;
  padding: 6px 14px;
  color: @text;
  background: @surface;
  border: 1px solid @border;
  border-radius: 7px;
  transition:
    border-color 0.15s ease,
    background-color 0.15s ease;

  &:hover:not(:disabled) {
    border-color: @accent;
  }

  &:disabled {
    cursor: not-allowed;
    color: @text-muted;
    background: @surface-muted;
  }

  &.primary {
    color: #ffffff;
    background: @accent;
    border-color: @accent;

    &:hover:not(:disabled) {
      background: #1d4ed8;
    }

    &:disabled {
      color: #ffffff;
      background: #93a7d8;
      border-color: #93a7d8;
    }
  }
}

.muted {
  margin: 0;
  color: @text-muted;
}

.error-text {
  margin: 0 0 10px;
  color: @danger;
  overflow-wrap: anywhere;
}

.kv {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 24px;
  margin: 0;

  > div {
    min-width: 0;
  }

  dt {
    margin-bottom: 2px;
    font-size: 12px;
    color: @text-muted;
  }

  dd {
    margin: 0;
    font-weight: 500;
  }

  &.compact {
    margin-top: 12px;
  }
}

.kv .wide {
  grid-column: 1 / -1;
}

.path {
  font-family: "Cascadia Code", Consolas, monospace;
  font-size: 12px;
  font-weight: 400;
  overflow-wrap: anywhere;
}

.check-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;

  li {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    background: @surface-muted;
    border: 1px solid @border;
    border-radius: 8px;
  }

  .dot {
    flex: 0 0 auto;
    width: 8px;
    height: 8px;
    margin-top: 6px;
    background: @danger;
    border-radius: 50%;
  }

  li.ok .dot {
    background: @success;
  }

  .check-copy {
    flex: 1;
    min-width: 0;
  }

  strong {
    font-size: 13px;
    font-weight: 600;
  }

  p {
    margin: 2px 0 0;
    font-size: 12px;
    color: @text-muted;
    overflow-wrap: anywhere;
  }

  .check-state {
    flex: 0 0 auto;
    font-size: 12px;
    color: @danger;
  }

  li.ok .check-state {
    color: @success;
  }
}

@media (max-width: 860px) {
  .card-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .hero {
    align-items: flex-start;
    flex-direction: column;
  }
}</style>
