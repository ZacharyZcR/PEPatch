# PEPatch

PE文件诊断与修改工具。

## 功能

- 🔍 PE文件结构分析
- 🛠️ PE文件修改
- 📊 诊断报告生成

## 安装

```bash
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest
```

## 使用

```bash
pepatch <pe-file>
```

## 开发

```bash
make test          # 运行测试
make lint          # 代码检查
make build         # 编译
make fmt           # 格式化
make install-hooks # 安装 Git Hooks
```

## 工程化

- ✅ Go 1.23
- ✅ CI/CD 自动化
- ✅ 代码质量检查
- ✅ Pre-commit Hooks
- ✅ GoReleaser 多平台发布

## 质量标准

- 圈复杂度 ≤15
- 认知复杂度 ≤20
- 导出函数必须有注释

## 发布

```bash
git tag v1.0.0
git push origin v1.0.0
```

支持平台：Linux/macOS/Windows，amd64/arm64
