# PEPatch

[![CI](https://github.com/ZacharyZcR/PEPatch/actions/workflows/ci.yml/badge.svg)](https://github.com/ZacharyZcR/PEPatch/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

强大的PE (Portable Executable) 文件分析和修改工具，支持深度分析、安全检测和精确修改。

## ✨ 核心特性

### 🔍 分析功能
- **完整结构分析**：PE头、节区、导入/导出表、资源、重定位
- **安全检测**：RWX权限节区、TLS回调、熵值分析
- **Code Cave检测**：识别可注入代码的空白区域
- **数字签名验证**：验证文件签名状态

### 🛠️ 修改功能
- **节区权限修改**：安全加固（移除危险的RWX权限）
- **入口点修改**：修改程序起始执行地址
- **节区注入**：添加自定义节区
- **导入表注入**：添加新的DLL导入，完美保留原始IAT
- **导出表修改**：添加、修改、删除DLL导出函数
- **数字签名移除**：移除PE文件的数字签名（可选截断）
- **TLS回调注入**：添加在主入口点前执行的TLS回调函数

### 🎯 技术亮点
- ✅ **保留原始IAT**：导入注入技术完全保留原始Import Address Table位置
- ✅ **PE32/PE32+双支持**：同时支持32位和64位PE文件
- ✅ **零依赖**：纯Go实现，无第三方依赖
- ✅ **跨平台**：Linux/macOS/Windows全平台支持

## 📦 安装

### 使用Go安装（推荐）

```bash
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest
```

### 从源码编译

```bash
git clone https://github.com/ZacharyZcR/PEPatch.git
cd PEPatch
go build -o pepatch ./cmd/pepatch
```

### 下载二进制

从[Releases页面](https://github.com/ZacharyZcR/PEPatch/releases)下载对应平台的二进制文件。

支持平台：
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64, arm64)

## 🚀 快速开始

### 基础分析

```bash
# 分析PE文件
pepatch C:\Windows\System32\notepad.exe

# 输出包括：
# - 文件基本信息（大小、架构、子系统）
# - PE头信息（入口点、镜像基址、校验和）
# - 节区信息（名称、大小、权限、熵值）
# - 导入/导出表摘要
# - 数字签名状态
```

### 高级分析

```bash
# 详细模式（显示所有导入函数）
pepatch -v program.exe

# 检测可疑节区（RWX权限）
pepatch -s suspicious.exe

# Code Cave检测
pepatch -caves -min-cave-size 64 program.exe

# 详细导入表
pepatch -list-imports program.exe

# 依赖分析（递归检测所有DLL依赖）
pepatch -deps program.exe
pepatch -deps -flat program.exe  # 扁平列表格式
```

### PE文件修改

```bash
# 修改节区权限（安全加固）
pepatch -patch -section .text -perms R-X program.exe    # 移除写权限
pepatch -patch -section .data -perms RW- program.exe    # 移除执行权限

# 修改入口点
pepatch -patch -entry 0x1000 program.exe

# 注入新节区
pepatch -patch -inject-section .newsec -section-size 8192 program.exe

# 导入表注入
pepatch -patch -add-import user32.dll:MessageBoxA,MessageBoxW program.exe

# 导出表修改
pepatch -patch -add-export MyFunction -export-rva 0x1000 mydll.dll       # 添加导出
pepatch -patch -modify-export OldFunc -export-rva 0x2000 mydll.dll      # 修改导出
pepatch -patch -remove-export UnusedFunc mydll.dll                       # 删除导出

# 数字签名移除
pepatch -patch -remove-signature program.exe                             # 移除签名（截断文件）
pepatch -patch -remove-signature -truncate-cert=false program.exe       # 移除签名（保留数据）

# TLS回调注入
pepatch -patch -add-tls-callback 0x1000 program.exe                      # 添加TLS回调
```

## 📖 文档

### 用户文档
- **[用户指南](docs/user-guide.md)** - 完整的使用说明和示例
- **[常见问题](docs/faq.md)** - 常见问题解答

### 技术文档
- **[架构设计](docs/architecture.md)** - 系统架构和设计理念
- **[导入注入技术](docs/import-injection.md)** - 核心技术深度解析

### 开发文档
- **[贡献指南](docs/contributing.md)** - 如何参与项目开发
- **[文档导航](docs/README.md)** - 完整文档索引

## 🎓 使用场景

### 安全分析

```bash
# 恶意软件分析流程
pepatch -v -caves -list-imports malware.exe > analysis.txt
grep -E "RWX|TLS|CreateRemoteThread|VirtualAlloc" analysis.txt
```

### 软件加固

```bash
# 批量加固应用程序
for exe in *.exe; do
    pepatch -patch -section .text -perms R-X "$exe"
    pepatch -patch -section .data -perms RW- "$exe"
done
```

### 逆向工程

```bash
# 查找可用于补丁注入的Code Caves
pepatch -caves -min-cave-size 128 target.exe

# 分析导入表了解程序功能
pepatch -list-imports target.exe
```

### DLL注入准备

```bash
# 通过导入表注入实现DLL自动加载
pepatch -patch -add-import hook.dll:Initialize target.exe
```

## 🏗️ 工程化

### 代码质量标准

- **圈复杂度** ≤ 15
- **认知复杂度** ≤ 20
- **测试覆盖率** > 80%
- **导出函数必须有注释**

### CI/CD流程

- ✅ **自动化测试**：每次提交自动运行完整测试套件
- ✅ **Lint检查**：golangci-lint严格代码质量检查
- ✅ **跨平台构建**：自动编译6个平台的二进制文件
- ✅ **自动发布**：Git tag触发自动发布到Releases

### 开发工具

```bash
make test          # 运行测试
make lint          # 代码检查
make build         # 编译
make fmt           # 格式化
make install-hooks # 安装 Git Hooks
```

## 🔬 技术实现

### 导入注入技术

PEPatch的核心创新是**完整重建导入表 + 保留原始IAT**的方案：

```
原始PE文件               修改后PE文件
┌──────────┐            ┌──────────┐
│ PE头     │            │ PE头     │──┐
├──────────┤            ├──────────┤  │
│ .text    │            │ .text    │  │
├──────────┤            ├──────────┤  │
│ .data    │            │ .data    │  │
│ ┌──────┐ │            │ ┌──────┐ │  │ 位置不变
│ │原始IAT│ │            │ │原始IAT│ │◄─┘
│ └──────┘ │            │ └──────┘ │
├──────────┤            ├──────────┤
│ .rdata   │            │ .rdata   │
│ (旧导入表)│            ├──────────┤
└──────────┘            │ .newimpt │◄─ 新导入节区
                        │ ┌──────┐ │
                        │ │完整   │ │
                        │ │导入表 │ │
                        │ └──────┘ │
                        └──────────┘
```

详见：[导入注入技术详解](docs/import-injection.md)

### 模块架构

```
cmd/pepatch/        # CLI入口
internal/pe/        # 核心功能
  ├── analyzer.go   # PE分析
  ├── patcher.go    # PE修改
  ├── import.go     # 导入表处理（23KB，最复杂）
  ├── section.go    # 节区操作
  ├── checksum.go   # 校验和计算
  ├── codecave.go   # Code Cave检测
  └── ...
```

详见：[架构设计](docs/architecture.md)

## 🤝 参与贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交改动 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

详见：[贡献指南](docs/contributing.md)

## 📄 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件

## 🙏 致谢

- Microsoft PE格式规范
- Go语言团队
- 所有贡献者

## 📞 联系方式

- **问题报告**：[GitHub Issues](https://github.com/ZacharyZcR/PEPatch/issues)
- **功能建议**：[GitHub Discussions](https://github.com/ZacharyZcR/PEPatch/discussions)
- **项目主页**：https://github.com/ZacharyZcR/PEPatch

---

**⚠️ 免责声明**：本工具仅用于合法的安全研究、软件开发和教育目的。请勿用于未经授权的系统访问或恶意活动。
