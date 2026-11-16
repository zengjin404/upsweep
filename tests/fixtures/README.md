# 测试夹具

本目录用于放置模拟软件目录。**阶段 0 尚未创建任何夹具；所有夹具必须是专门生成的无害文件。**

计划结构（阶段 1 起使用，依据 DEVELOPMENT.md 第 12.1 节）：

```text
fixtures/
├── software-a/
│   ├── updater/installer.exe
│   └── app.exe
├── software-b/
│   ├── upgrade/package/PixPin_2.0.0.3.exe
│   └── config.json
├── software-c/
│   └── update/old-setup.exe
│       update/unknown.dat
├── software-d/
│   └── updater/updater.exe
└── protected/
    └── Windows/installer.exe
```

安全规则：

- 不得扫描、修改或删除用户真实软件目录、系统目录。
- 不得使用真实系统文件或可执行安装包作为夹具。
- 夹具文件可用任意占位字节生成，不得实际执行。
- 涉及移动/删除的测试只在临时副本上进行，测试结束清理。
