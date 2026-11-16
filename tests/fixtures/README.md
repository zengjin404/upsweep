# 测试夹具

本目录只包含专门生成的无害夹具，不包含真实安装包或用户文件。

## 当前结构

```text
fixtures/
├── metadata/
│   ├── plain.exe             # 无版本资源的 PE
│   ├── versioned.exe         # 带版本资源（ProductName=UpSweep Fixture）
│   ├── signed-self.exe       # 使用临时自签名证书签名，未加入系统信任
│   ├── signed-tampered.exe   # 自签名后篡改 PE 字节，签名摘要无效
│   ├── corrupt.exe           # 非 PE 内容，.exe 扩展名
│   └── src/                  # 版本资源源码（plain.c / versioned.rc）
├── software-a/
│   ├── updater/installer.exe # 版本资源 PE
│   └── app.exe               # 普通 EXE（无更新目录/文件名特征）
├── software-b/
│   └── upgrade/package/
│       ├── PixPin_2.0.0.3.exe
│       └── PixPin_2.0.0.3.msi
├── software-c/
│   └── update/
│       ├── old-setup.exe
│       ├── corrupt.exe
│       ├── patch.msp
│       ├── unknown.dat
│       └── cache/cached-installer.exe
├── software-d/
│   └── updater/updater.exe
├── software-e/vendor/BetaUpdater/PixPin_2.0.0.2.exe
├── normal/app.exe
├── paths/中文 空格/安装程序_2.0.0.1.exe
└── protected/Windows/installer.exe
```

- PE 夹具由 MSVC `rc.exe` / `cl.exe` 从 `metadata/src` 生成，只有导出的 EXE 被提交。
- MSI/MSP 由 `src-tauri/examples/make-fixture-msi.rs` 一次性生成；可重复运行该示例重建。
- `signed-self.exe` 的私钥/证书未提交，仅保留签名后的 EXE。
- Junction、Symbolic Link、长路径、无权限目录在测试运行时于临时目录生成，不提交。

## 安全规则

- 不得扫描、修改或删除用户真实软件目录、系统目录。
- 不得使用真实系统文件或可执行安装包作为夹具。
- 夹具文件不得实际执行；测试只读取属性/版本资源/签名结构/MSI 表。
- 涉及移动/删除的测试只在临时副本上进行，测试结束清理。
