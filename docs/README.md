# PEPatch 文档

欢迎使用PEPatch文档！

## 📖 文档导航

### 用户文档
- [用户指南](user-guide.md) - 完整的使用说明和示例
- [常见问题](faq.md) - 常见问题解答

### 技术文档
- [架构设计](architecture.md) - 系统架构和设计理念
- [导入注入技术](import-injection.md) - 核心技术深度解析
- [API参考](api.md) - 库API文档

### 开发文档
- [贡献指南](contributing.md) - 如何参与项目开发
- [代码结构](code-structure.md) - 代码组织说明

## 🚀 快速开始

```bash
# 安装
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest

# 分析PE文件
pepatch C:\Windows\System32\notepad.exe

# 修改PE文件
pepatch -patch -section .text -perms R-X program.exe
```

## 🎯 核心功能

### 分析功能
- PE结构全面分析（头部、节区、导入/导出表）
- 数字签名验证
- 熵值计算（检测加壳/加密）
- Code Cave检测
- 安全风险识别（RWX节区、TLS回调）

### 修改功能
- 节区权限修改
- 入口点修改
- 节区注入
- **导入表注入**（保留原始IAT，完美兼容）

## 📊 项目质量

- ✅ 圈复杂度 ≤15
- ✅ 认知复杂度 ≤20
- ✅ CI/CD自动化
- ✅ 跨平台支持
- ✅ 完整单元测试

## 📧 联系方式

- GitHub Issues: [提交问题](https://github.com/ZacharyZcR/PEPatch/issues)
- 贡献代码: 参考[贡献指南](contributing.md)
