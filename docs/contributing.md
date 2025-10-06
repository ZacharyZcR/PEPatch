# 贡献指南

感谢您对PEPatch的关注！本指南将帮助您参与项目开发。

## 目录

- [开发环境设置](#开发环境设置)
- [代码规范](#代码规范)
- [提交流程](#提交流程)
- [测试要求](#测试要求)
- [文档规范](#文档规范)
- [问题报告](#问题报告)

## 开发环境设置

### 必要工具

**Go环境**：
```bash
# 安装Go 1.21+
# https://golang.org/dl/

# 验证安装
go version  # 应显示 go1.21 或更高
```

**Linter工具**：
```bash
# 安装golangci-lint
# https://golangci-lint.run/usage/install/

# Linux/macOS
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Windows
# 下载并安装二进制文件

# 验证安装
golangci-lint version
```

**Git配置**：
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 克隆项目

```bash
# Fork项目到您的GitHub账户
# 然后克隆您的fork

git clone https://github.com/YOUR_USERNAME/PEPatch.git
cd PEPatch

# 添加上游仓库
git remote add upstream https://github.com/ZacharyZcR/PEPatch.git

# 验证
git remote -v
```

### 构建项目

```bash
# 下载依赖（如有）
go mod download

# 编译
go build -o pepatch ./cmd/pepatch

# 运行
./pepatch -h
```

### 运行测试

```bash
# 运行所有测试
go test -v ./...

# 运行特定包的测试
go test -v ./internal/pe

# 查看覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### 运行Lint检查

```bash
# 运行golangci-lint
golangci-lint run

# 仅检查特定目录
golangci-lint run ./internal/pe

# 自动修复（慎用）
golangci-lint run --fix
```

## 代码规范

### 复杂度限制

**严格执行**：
- 圈复杂度 (Cyclomatic Complexity) ≤ 15
- 认知复杂度 (Cognitive Complexity) ≤ 20

**检查工具**：
```bash
golangci-lint run
```

**如何降低复杂度**：

```go
// ❌ 复杂度过高（嵌套过深）
func processData(data []byte) error {
    if len(data) > 0 {
        if data[0] == 0x4D {
            if data[1] == 0x5A {
                for i := 0; i < len(data); i++ {
                    if data[i] == 0x00 {
                        // 深层嵌套...
                    }
                }
            }
        }
    }
    return nil
}

// ✅ 拆分函数，降低复杂度
func processData(data []byte) error {
    if !isValidData(data) {
        return fmt.Errorf("invalid data")
    }

    return processValidData(data)
}

func isValidData(data []byte) bool {
    return len(data) >= 2 && data[0] == 0x4D && data[1] == 0x5A
}

func processValidData(data []byte) error {
    for i := 0; i < len(data); i++ {
        if err := processElement(data[i]); err != nil {
            return err
        }
    }
    return nil
}
```

### 命名规范

**变量命名**：
```go
// ✅ 清晰的命名
importDescriptorSize := 20
sectionAlignment := 0x1000
originalIATAddress := section.VirtualAddress

// ❌ 模糊的命名
size := 20
align := 0x1000
addr := section.VirtualAddress
```

**函数命名**：
```go
// ✅ 动词开头，清晰表达意图
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error
func (p *PEPatcher) ModifySectionPermissions(name, perms string) error
func CalculateEntropy(data []byte) float64

// ❌ 名词或不清晰
func (p *PEPatcher) Import(dll string, funcs []string) error
func (p *PEPatcher) Section(n, p string) error
func Entropy(d []byte) float64
```

**常量命名**：
```go
// ✅ 全大写，下划线分隔（Windows SDK风格）
const IMAGE_DIRECTORY_ENTRY_IMPORT = 1
const SECTION_ALIGNMENT = 0x1000

// ✅ 驼峰命名（Go风格）- 两种都可以
const ImageDirectoryEntryImport = 1
const SectionAlignment = 0x1000
```

### 注释规范

**公开函数必须有文档注释**：
```go
// AddImport injects a new DLL import into the PE file.
// It creates a new import section with import descriptors, INT, IAT, and string data.
//
// Parameters:
//   - dllName: Name of the DLL to import (e.g., "user32.dll")
//   - funcNames: List of function names to import from the DLL
//
// Returns:
//   - error if the import injection fails
//
// Example:
//   err := patcher.AddImport("user32.dll", []string{"MessageBoxA", "MessageBoxW"})
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error {
    // 实现...
}
```

**复杂逻辑需要解释**：
```go
// Calculate the total size needed for the new import section.
// Layout:
//   1. Import Descriptors (20 bytes each + null terminator)
//   2. INT arrays (8 bytes per entry for PE32+, + null terminators)
//   3. IAT arrays (same as INT)
//   4. String data (DLL names + function names with hints)
descriptorSize := (len(allDLLs) + 1) * 20  // +1 for null descriptor
intSize := calculateINTSize(allDLLs)
iatSize := calculateIATSize(newDLL)
stringSize := calculateStringSize(allDLLs)

totalSize := descriptorSize + intSize + iatSize + stringSize
```

**避免无用注释**：
```go
// ❌ 无用的注释
// increment i
i++

// ✅ 有价值的注释
// Skip the DOS stub (typically 64 bytes after DOS header)
offset += 64
```

### 错误处理

**明确的错误信息**：
```go
// ✅ 提供上下文信息
if section == nil {
    return fmt.Errorf("section %s not found in PE file", sectionName)
}

if len(data) < requiredSize {
    return fmt.Errorf("insufficient data: got %d bytes, need %d", len(data), requiredSize)
}

// ❌ 模糊的错误
if section == nil {
    return errors.New("section not found")
}

if len(data) < requiredSize {
    return errors.New("data too small")
}
```

**错误包装**：
```go
// ✅ 包装错误，保留上下文
if err := p.AddSection(name, size, perms); err != nil {
    return fmt.Errorf("failed to add section %s: %w", name, err)
}

// ❌ 丢失上下文
if err := p.AddSection(name, size, perms); err != nil {
    return err
}
```

### 代码格式

**使用gofmt**：
```bash
# 格式化所有文件
gofmt -w .

# 检查格式（CI使用）
gofmt -l . | grep -E '.+' && exit 1 || exit 0
```

**行长度**：
- 优先保持 < 100字符
- 最大不超过120字符

**导入顺序**：
```go
import (
    // 标准库
    "encoding/binary"
    "fmt"
    "os"

    // 第三方库（如有）
    "github.com/third/party"

    // 本地包
    "github.com/ZacharyZcR/PEPatch/internal/pe"
)
```

## 提交流程

### 1. 创建分支

```bash
# 更新主分支
git checkout main
git pull upstream main

# 创建特性分支
git checkout -b feature/your-feature-name
# 或
git checkout -b fix/bug-description
```

**分支命名规范**：
- `feature/` - 新功能
- `fix/` - Bug修复
- `docs/` - 文档更新
- `refactor/` - 代码重构
- `test/` - 测试改进

### 2. 开发

```bash
# 进行开发
vim internal/pe/newfeature.go

# 频繁提交
git add .
git commit -m "Add initial implementation of new feature"

# 继续开发
git commit -m "Refine new feature implementation"
git commit -m "Add tests for new feature"
```

### 3. 提交信息规范

**格式**：
```
<type>: <subject>

<body>

<footer>
```

**Type类型**：
- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更新
- `style`: 格式调整（不影响代码逻辑）
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具链相关

**示例**：
```
feat: Add support for import table injection

Implement the core functionality to inject new DLL imports while
preserving the original IAT location. This uses Solution 4 approach
with complete import table reconstruction.

- Add AddImport() method to PEPatcher
- Implement import descriptor writing
- Add INT/IAT creation logic
- Include comprehensive tests

Closes #123
```

```
fix: Correct RVA calculation in import injection

The previous calculation didn't account for section alignment,
causing crashes when the new import section was not properly aligned.

Fixed by using alignTo() helper and updating RVA offsets accordingly.

Fixes #456
```

### 4. 测试和Lint

```bash
# 运行测试
go test -v ./...

# 运行lint
golangci-lint run

# 检查格式
gofmt -l . | grep -E '.+' && echo "需要格式化" || echo "格式正确"
```

### 5. 推送和创建PR

```bash
# 推送到您的fork
git push origin feature/your-feature-name

# 在GitHub上创建Pull Request
# 标题：简洁描述（与commit subject一致）
# 描述：详细说明改动内容、测试方法
```

**PR描述模板**：
```markdown
## 改动内容
简要描述本PR的改动

## 改动类型
- [ ] 新功能
- [ ] Bug修复
- [ ] 文档更新
- [ ] 重构
- [ ] 测试改进

## 测试
说明如何测试本改动

## 检查清单
- [ ] 代码通过golangci-lint检查
- [ ] 添加了单元测试
- [ ] 测试覆盖核心逻辑
- [ ] 更新了相关文档
- [ ] Commit信息清晰明确

## 相关Issue
Closes #123
```

### 6. Code Review

**准备接受反馈**：
- 维护者可能要求修改
- 积极回应评论
- 根据反馈进行调整

**修改后更新PR**：
```bash
# 在同一分支继续修改
git add .
git commit -m "Address review comments"
git push origin feature/your-feature-name

# PR会自动更新
```

## 测试要求

### 单元测试

**每个新功能都需要测试**：
```go
// internal/pe/newfeature_test.go
package pe

import (
    "testing"
)

func TestNewFeature(t *testing.T) {
    // 准备测试数据
    patcher, err := NewPEPatcher("testdata/sample.exe")
    if err != nil {
        t.Fatalf("Failed to load PE: %v", err)
    }

    // 执行功能
    err = patcher.NewFeature(params)
    if err != nil {
        t.Errorf("NewFeature failed: %v", err)
    }

    // 验证结果
    if result != expected {
        t.Errorf("Expected %v, got %v", expected, result)
    }
}
```

### 测试覆盖率

**目标**：
- 新代码覆盖率 ≥ 80%
- 核心功能覆盖率 ≥ 90%

**检查覆盖率**：
```bash
go test -coverprofile=coverage.out ./internal/pe
go tool cover -func=coverage.out

# 查看HTML报告
go tool cover -html=coverage.out
```

### 边界情况测试

```go
func TestNewFeature_EdgeCases(t *testing.T) {
    tests := []struct {
        name    string
        input   interface{}
        wantErr bool
    }{
        {"empty input", "", true},
        {"nil input", nil, true},
        {"invalid format", "invalid", true},
        {"valid input", "valid", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := patcher.NewFeature(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
            }
        })
    }
}
```

### 测试数据

**使用testdata目录**：
```
testdata/
├── pe32/
│   ├── simple.exe       # 简单PE32文件
│   └── complex.exe      # 复杂PE32文件
├── pe32plus/
│   ├── simple.exe       # 简单PE64文件
│   └── complex.exe      # 复杂PE64文件
└── invalid/
    ├── truncated.exe    # 截断的文件
    └── corrupted.exe    # 损坏的文件
```

**不要提交大文件**：
- 测试文件应尽量小（< 100KB）
- 使用最小化的测试样本

## 文档规范

### 代码文档

**公开API必须有文档**：
```go
// Package pe provides PE (Portable Executable) file analysis and modification capabilities.
//
// It supports both PE32 (32-bit) and PE32+ (64-bit) formats and offers:
//   - Structure analysis (headers, sections, imports, exports)
//   - Security analysis (entropy, code caves, suspicious sections)
//   - Modification operations (permissions, entry point, section injection, import injection)
//
// Example:
//   patcher, err := pe.NewPEPatcher("program.exe")
//   if err != nil {
//       log.Fatal(err)
//   }
//   err = patcher.AddImport("user32.dll", []string{"MessageBoxA"})
package pe
```

### Markdown文档

**更新相关文档**：
- 新功能 → 更新 `docs/user-guide.md`
- 架构改动 → 更新 `docs/architecture.md`
- API变化 → 更新 `docs/api.md`

**文档风格**：
- 清晰的标题层次
- 代码示例有注释
- 包含实际使用场景

### README更新

**当添加新功能时**：
```markdown
## Features

- ✅ PE structure analysis
- ✅ Import/Export table parsing
- ✅ Code cave detection
- ✅ **New Feature** (新添加的)
```

## 问题报告

### 提交Bug报告

**模板**：
```markdown
### 环境信息
- OS: Windows 10 / Linux / macOS
- PEPatch版本: v1.0.0
- Go版本: go1.21.0

### 问题描述
清晰描述遇到的问题

### 复现步骤
1. 运行命令 `pepatch -patch ...`
2. 观察到...
3. 预期应该...

### 错误输出
```
[粘贴完整的错误信息]
```

### 测试文件（如果可能）
附上能复现问题的PE文件（或说明如何生成）
```

### 提交功能请求

**模板**：
```markdown
### 功能描述
我希望PEPatch能够...

### 使用场景
这个功能在以下场景很有用：
1. ...
2. ...

### 建议实现方案（可选）
可以通过...来实现

### 替代方案
目前可以通过...来部分达到目的，但是...
```

## 社区准则

### 行为准则

- **尊重**：尊重所有贡献者
- **建设性**：提供建设性的反馈
- **耐心**：对新手保持耐心
- **专业**：保持技术讨论的专业性

### 沟通渠道

- **GitHub Issues**: 问题报告、功能请求
- **Pull Requests**: 代码贡献、讨论
- **Discussions**: 一般性讨论、问题求助

## 常见问题

### Q: 我的PR何时会被审核？

A: 通常在1-3个工作日内。如果超过一周未回应，可以礼貌地ping维护者。

### Q: CI检查失败了怎么办？

A: 查看失败日志，通常是：
- Lint错误：运行 `golangci-lint run` 查看
- 测试失败：运行 `go test -v ./...` 检查
- 格式问题：运行 `gofmt -w .` 修复

### Q: 如何选择合适的Issue开始贡献？

A: 寻找标签为 `good first issue` 或 `help wanted` 的Issue。

### Q: 我不熟悉Go语言可以贡献吗？

A: 可以！您可以从以下方面贡献：
- 文档改进
- 测试用例
- Bug报告
- 功能建议

### Q: 复杂度检查太严格了，我的合理代码也通不过？

A: 复杂度限制是为了代码质量。如果确实必要，可以：
1. 尝试重构（推荐）
2. 在PR中说明原因，寻求豁免（罕见）

## 致谢

感谢每一位贡献者！您的参与让PEPatch变得更好。

### 主要贡献者

- [@ZacharyZcR](https://github.com/ZacharyZcR) - 项目创始人

### 贡献者列表

[GitHub Contributors](https://github.com/ZacharyZcR/PEPatch/graphs/contributors)

---

再次感谢您的贡献！🎉
