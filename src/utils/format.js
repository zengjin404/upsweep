const UNITS = ["KB", "MB", "GB", "TB"];

/**
 * 将字节数格式化为便于阅读的字符串。
 * 非数字、负数或非有限值返回占位符，避免界面出现 NaN。
 */
export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || bytes === "") {
    return "—";
  }

  const value = Number(bytes);
  if (!Number.isFinite(value) || value < 0) {
    return "—";
  }

  if (value < 1024) {
    return `${value} B`;
  }

  let scaled = value / 1024;
  let unitIndex = 0;
  while (scaled >= 1024 && unitIndex < UNITS.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }

  const digits = scaled >= 10 ? 0 : 1;
  return `${scaled.toFixed(digits)} ${UNITS[unitIndex]}`;
}
