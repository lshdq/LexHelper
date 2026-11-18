# LexHelper 项目规范

- 技术栈：Windows 10/11 x64、C++23、VS2026 Build Tools v145、Win32 GUI、CMake。操作前读取全局 `D:\Program\opencode\data\config\opencode\rules\Windows桌面-C++23.md`；不自动安装或升级工具。
- 项目指令仅放本文件，禁止在项目根目录生成 AGENTS.md。确认有效全局配置 instructions 包含 `.opencode/AGENTS.md` 才可声称自动加载。
- C++ 源 UTF-8；公开 API 使用 `lexhelper` 命名空间，路径用 `std::filesystem::path`，文本边界明确 UTF-8/UTF-16，不使用 ANSI 代码页。
- 解析器视所有输入为不可信：检查大小、长度、偏移、整数、Unicode、重复项及 ZIP 结构；任何错误拒绝整体导入，不静默截断或跳行。
- 私人 CWB 不入库/上传，测试仅构造样本；真实样本通过 `LEXHELPER_CWB_SAMPLE` 显式启用。不得打印个人配置。
- 运行程序不得依赖 .NET/PowerShell/Python。第三方源码保留原始许可证及来源；离线构建，不自动抓取依赖。
- 默认在当前分支工作，不自动 commit/push；修改代码遵循全局 dev-workflow，独立开发/测试/审查阶段不递归委派。
- 自动测试不得替换系统 lex、修改系统 ACL 或终止输入法/文本服务。部署只能对临时模拟目录测试；真实安装须用户明确确认。
- 默认无管理员预览，安装入口最小权限；无可靠热刷新则提示注销，禁止强杀 ctfmon/共享文本服务。
- 保存拒绝覆盖；备份不可覆盖；权限、回滚、未知文件与路径联接均须显式处理。所有 Win32 资源使用 RAII，不让异常越过系统回调。
- 构建：`cmake --preset vs2026`、`cmake --build --preset debug`、`ctest --preset debug`（Release 对应 release）。独立子任务用不同 binaryDir，不并发写同一 out。
- AI 临时制品只放 `D:\temp\aiRunner\opencode` 下本任务唯一目录；依全局规则核实容量、持久保存证据后仅清理本任务制品，不回退 C 盘。
