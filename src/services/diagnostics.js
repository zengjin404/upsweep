import { invoke } from "@tauri-apps/api/core";

// 所有后端调用集中在此文件，组件不直接拼接命令名。
export function getAppInfo() {
  return invoke("get_app_info");
}

export function runDatabaseCheck() {
  return invoke("run_database_check");
}

export function probeWindowsApi() {
  return invoke("probe_windows_api");
}
