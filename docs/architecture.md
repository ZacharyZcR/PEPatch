# 架构设计

本文档介绍PEPatch的系统架构、设计理念和模块组织。

## 目录

- [设计哲学](#设计哲学)
- [整体架构](#整体架构)
- [模块设计](#模块设计)
- [代码质量标准](#代码质量标准)
- [CI/CD流程](#cicd流程)
- [扩展性设计](#扩展性设计)

## 设计哲学

### 核心原则

**1. 简洁性 (Simplicity)**
> "如果实现需要超过3层缩进，重新设计它。" - Linux内核编码规范

- 每个函数只做一件事
- 圈复杂度 ≤ 15
- 认知复杂度 ≤ 20
- 避免过度抽象

**2. 可读性 (Readability)**
> "代码是写给人看的，顺便让机器执行。"

- 清晰的命名（变量、函数、类型）
- 完整的注释（公开API必须有文档）
- 结构化的代码组织

**3. 可靠性 (Reliability)**
> "Never break userspace."

- 完整的错误处理
- 自动备份机制
- 严格的输入验证
- 全面的单元测试

**4. 实用主义 (Pragmatism)**
> "解决实际问题，而不是假想的威胁。"

- 优先级：功能 > 性能 > 优雅
- 避免过度设计
- 测试覆盖真实场景

## 整体架构

### 分层架构

```
┌─────────────────────────────────────────────────────┐
│              CLI Layer (cmd/pepatch)                │
│  - 参数解析                                          │
│  - 输出格式化                                        │
│  - 用户交互                                          │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────┴─────────────────────────────┐
│          Application Layer (internal/pe)            │
│                                                      │
│  ┌────────────────┐        ┌─────────────────┐     │
│  │   Analyzer     │        │    Patcher      │     │
│  │  - 结构分析    │        │  - 权限修改     │     │
│  │  - 安全检测    │        │  - 入口点修改   │     │
│  │  - 导入导出    │        │  - 节区注入     │     │
│  └────────────────┘        │  - 导入注入     │     │
│                            └─────────────────┘     │
│                                                      │
│  ┌──────────────────────────────────────────────┐  │
│  │          Core Modules                        │  │
│  │  - Import/Export  - Section   - Checksum    │  │
│  │  - CodeCave       - Entropy   - Signature   │  │
│  │  - TLS            - Resource  - Relocation  │  │
│  └──────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────┴─────────────────────────────┐
│           PE File I/O Layer                         │
│  - 文件读写                                          │
│  - 结构解析                                          │
│  - 二进制操作                                        │
└─────────────────────────────────────────────────────┘
```

### 数据流

**分析模式**：
```
PE文件 → Reader → Analyzer → 结构化数据 → Formatter → 用户输出
```

**修改模式**：
```
PE文件 → Reader → Patcher → 修改操作 → Writer → 备份 → 新PE文件
```

## 模块设计

### 1. CLI模块 (`cmd/pepatch`)

**职责**：
- 解析命令行参数
- 调用核心功能
- 格式化输出
- 错误处理和用户提示

**关键文件**：
```
cmd/pepatch/
├── main.go           # 主程序入口
├── flags.go          # 参数定义
├── analyzer.go       # 分析命令处理
└── patcher.go        # 修改命令处理
```

**设计要点**：
- 使用`flag`标准库（简单有效）
- 清晰的帮助信息
- 友好的错误提示

### 2. PE核心模块 (`internal/pe`)

#### 2.1 Reader/Writer

**reader.go**：
```go
type PEPatcher struct {
    Data        []byte           // 原始PE文件数据
    DosHeader   *DosHeader       // DOS头
    NTHeaders   *NTHeaders       // NT头
    Sections    []*SectionHeader // 节区表
    Is64Bit     bool             // PE32/PE32+标识
    // ...
}

// 核心方法
func NewPEPatcher(filePath string) (*PEPatcher, error)
func (p *PEPatcher) Save(filePath string) error
```

**设计要点**：
- 一次性读取整个文件到内存（简单可靠）
- 统一的错误处理
- 自动识别PE32/PE32+

#### 2.2 Analyzer

**analyzer.go** (5718 bytes)：
```go
// 公开API
func (p *PEPatcher) Analyze() (*AnalysisResult, error)
func (p *PEPatcher) GetBasicInfo() BasicInfo
func (p *PEPatcher) GetSections() []SectionInfo
func (p *PEPatcher) GetImportSummary() []ImportedDLL
```

**分析内容**：
- 文件基本信息（大小、架构、子系统）
- PE头信息（入口点、镜像基址）
- 节区分析（权限、大小、熵值）
- 导入/导出表摘要
- 数字签名状态
- TLS回调检测

**设计要点**：
- 非侵入式（只读，不修改）
- 结构化输出（便于程序化处理）
- 性能优化（缓存解析结果）

#### 2.3 Patcher

**patcher.go** (6877 bytes)：
```go
// 修改操作
func (p *PEPatcher) ModifySectionPermissions(name, perms string) error
func (p *PEPatcher) ModifyEntryPoint(newEP uint32) error
func (p *PEPatcher) InjectSection(name string, size uint32, perms string) error
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error
```

**设计要点**：
- 每个操作都是原子的
- 完整的回滚机制（通过备份）
- 详细的日志输出

#### 2.4 Import模块

**import.go** (23379 bytes) - 最复杂的模块：

```go
// 导入表操作
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error
func (p *PEPatcher) parseImports() []ImportedDLL
func (p *PEPatcher) buildImportData(...) ([]byte, error)

// 内部实现
func (p *PEPatcher) writeImportDescriptors(...) uint32
func (p *PEPatcher) writeImportNameTables(...) uint32
func (p *PEPatcher) writeImportAddressTables(...) uint32
func (p *PEPatcher) writeImportStrings(...) uint32
```

**复杂度来源**：
- PE32/PE32+双重支持
- 序号/名称导入兼容
- IAT位置保留逻辑
- 精确的RVA计算

**设计要点**：
- 函数拆分（每个函数 < 80行）
- 清晰的数据布局规划
- 完整的注释说明

详见：[导入注入技术](import-injection.md)

#### 2.5 辅助模块

**checksum.go** (2922 bytes)：
```go
func (p *PEPatcher) UpdateChecksum() error
func calculatePEChecksum(data []byte) uint32
```
- 实现PE文件校验和算法
- 自动更新Optional Header

**codecave.go** (4945 bytes)：
```go
func (p *PEPatcher) FindCodeCaves(minSize int) []CodeCave
```
- 检测填充区域（0x00或0xCC）
- 支持自定义最小大小

**entropy.go**：
```go
func CalculateEntropy(data []byte) float64
```
- Shannon熵值计算
- 加壳/加密检测

**section.go** (8671 bytes)：
```go
func (p *PEPatcher) GetSection(name string) *SectionHeader
func (p *PEPatcher) AddSection(...) error
func (p *PEPatcher) parseSectionPermissions(chars uint32) string
```
- 节区操作核心逻辑
- 权限解析和修改

**signature.go**：
```go
func (p *PEPatcher) VerifySignature() bool
func (p *PEPatcher) GetSignatureInfo() SignatureInfo
```
- 数字签名验证
- 证书信息提取

**export.go**, **tls.go**, **resource.go**, **relocation.go**：
- Export Table解析
- TLS回调检测
- Resource Directory分析
- Relocation Table处理

## 代码质量标准

### 复杂度控制

使用`golangci-lint`强制执行：

```yaml
gocyclo:
  min-complexity: 15    # 圈复杂度阈值

gocognit:
  min-complexity: 20    # 认知复杂度阈值
```

**圈复杂度 (Cyclomatic Complexity)**：
- 衡量代码路径数量
- 计算方法：if/for/case等分支 + 1
- 超过15需要重构

**认知复杂度 (Cognitive Complexity)**：
- 衡量代码理解难度
- 考虑嵌套层次
- 超过20需要重构

### 代码规范

**命名规范**：
```go
// ✅ 好的命名
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error
var importDescriptorSize = 20
const sectionAlignment = 0x1000

// ❌ 差的命名
func (p *PEPatcher) DoStuff(s string, arr []string) error
var size = 20
const X = 0x1000
```

**注释规范**：
```go
// ✅ 公开函数必须有文档注释
// AddImport injects a new DLL import into the PE file.
// It creates a new import descriptor and updates the Import Directory.
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error

// ✅ 复杂逻辑需要解释
// Calculate the total size needed for the new import section:
// - Import Descriptors (20 bytes each, plus null terminator)
// - INT arrays (pointer size per entry, plus null terminators)
// - IAT arrays (same as INT)
// - String data (DLL names + function names)
totalSize := descriptorSize + intSize + iatSize + stringSize
```

**错误处理**：
```go
// ✅ 明确的错误信息
if section == nil {
    return fmt.Errorf("section %s not found", name)
}

// ❌ 模糊的错误
if section == nil {
    return errors.New("error")
}
```

### 测试策略

**单元测试**：
```
internal/pe/
├── analyzer_test.go
├── import_test.go
├── patcher_test.go
├── section_test.go
└── ...
```

**测试覆盖**：
- 核心功能：>80%覆盖率
- 边界情况：空文件、损坏文件、特殊PE
- 回归测试：已修复的bug

**测试数据**：
```
testdata/
├── pe32/
│   ├── simple.exe
│   └── complex.exe
├── pe32plus/
│   ├── simple.exe
│   └── complex.exe
└── invalid/
    ├── truncated.exe
    └── corrupted.exe
```

## CI/CD流程

### GitHub Actions工作流

```yaml
name: CI

on: [push, pull_request]

jobs:
  lint:
    - golangci-lint run
    - go fmt check
    - go vet

  test:
    - go test -v -race ./...
    - go test -coverprofile=coverage.out

  build:
    - go build ./cmd/pepatch
    - Cross-compile for Linux/macOS/Windows
```

### 质量门禁

**Lint阶段**：
- ✅ golangci-lint通过
- ✅ gofmt格式检查
- ✅ go vet静态分析

**Test阶段**：
- ✅ 所有单元测试通过
- ✅ 竞态检测通过
- ✅ 覆盖率达标

**Build阶段**：
- ✅ 编译成功（多平台）
- ✅ 二进制文件正常运行

只有所有检查通过，才允许合并PR。

## 扩展性设计

### 添加新的分析功能

1. 在`analyzer.go`中添加方法：
```go
func (p *PEPatcher) AnalyzeNewFeature() NewFeatureInfo {
    // 实现分析逻辑
}
```

2. 在`main.go`中添加命令行选项：
```go
var analyzeNewFeature = flag.Bool("new-feature", false, "Analyze new feature")
```

3. 添加单元测试：
```go
func TestAnalyzeNewFeature(t *testing.T) {
    // 测试逻辑
}
```

### 添加新的修改功能

1. 在`patcher.go`中添加方法：
```go
func (p *PEPatcher) ModifyNewThing(params ...interface{}) error {
    // 1. 验证输入
    // 2. 执行修改
    // 3. 更新PE头
    // 4. 返回结果
}
```

2. 确保原子性（备份机制）：
```go
// 调用者负责备份
if *backup {
    createBackup(filePath)
}
patcher.ModifyNewThing(...)
patcher.Save(filePath)
```

3. 完整测试：
```go
func TestModifyNewThing(t *testing.T) {
    // 1. 准备测试文件
    // 2. 执行修改
    // 3. 验证结果
    // 4. 测试回滚
}
```

### 支持新的PE特性

如需支持新的PE结构（如.NET元数据）：

1. 定义数据结构：
```go
type CLRHeader struct {
    Size              uint32
    MajorVersion      uint16
    MinorVersion      uint16
    Metadata          DataDirectory
    Flags             uint32
    // ...
}
```

2. 实现解析：
```go
func (p *PEPatcher) parseCLRHeader() (*CLRHeader, error) {
    // 解析逻辑
}
```

3. 集成到分析流程：
```go
func (p *PEPatcher) Analyze() (*AnalysisResult, error) {
    // 现有分析...

    if p.isManagedExecutable() {
        result.CLRInfo = p.parseCLRHeader()
    }

    return result, nil
}
```

## 依赖管理

### 依赖原则

**最小化外部依赖**：
- 优先使用Go标准库
- 只引入必要的第三方库
- 避免重依赖（大型框架）

**当前依赖**：
```go
// 标准库
import (
    "encoding/binary"
    "fmt"
    "os"
    "io/ioutil"
    "flag"
    // ...
)

// 第三方库（无）
// PEPatch目前零第三方依赖
```

**优势**：
- ✅ 编译快速
- ✅ 二进制体积小
- ✅ 安全性高（无供应链风险）
- ✅ 维护简单

### 版本管理

使用Go Modules：
```
go.mod:
module github.com/ZacharyZcR/PEPatch

go 1.21

// 目前无外部依赖
```

## 性能考量

### 内存管理

**一次性读取 vs 流式处理**：

目前采用一次性读取：
```go
data, err := ioutil.ReadFile(filePath)
```

**优势**：
- 代码简单
- 随机访问方便
- 性能足够（PE文件通常 < 100MB）

**未来优化**（如需处理GB级文件）：
- 实现内存映射（mmap）
- 流式处理大型节区

### 算法优化

**熵值计算**：
```go
// O(n) 单遍扫描
func CalculateEntropy(data []byte) float64 {
    freq := make([]int, 256)
    for _, b := range data {
        freq[b]++
    }
    // 计算Shannon熵
}
```

**Code Cave检测**：
```go
// O(n) 线性扫描
func FindCodeCaves(data []byte, minSize int) []CodeCave {
    // 单遍扫描，记录连续空白区域
}
```

## 安全考量

### 输入验证

```go
// 验证PE文件有效性
if !p.isValidPE() {
    return fmt.Errorf("invalid PE file")
}

// 验证节区名称
if !isValidSectionName(name) {
    return fmt.Errorf("invalid section name")
}

// 验证权限字符串
if !isValidPermissions(perms) {
    return fmt.Errorf("invalid permissions format")
}
```

### 备份机制

```go
// 自动备份
if *backup {
    backupPath := filePath + ".bak"
    if err := copyFile(filePath, backupPath); err != nil {
        return fmt.Errorf("backup failed: %v", err)
    }
}
```

### 数据完整性

```go
// 可选的校验和更新
if *updateChecksum {
    if err := patcher.UpdateChecksum(); err != nil {
        return fmt.Errorf("checksum update failed: %v", err)
    }
}
```

## 平台兼容性

### 跨平台编译

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o pepatch-linux ./cmd/pepatch

# macOS
GOOS=darwin GOARCH=amd64 go build -o pepatch-macos ./cmd/pepatch
GOOS=darwin GOARCH=arm64 go build -o pepatch-macos-m1 ./cmd/pepatch

# Windows
GOOS=windows GOARCH=amd64 go build -o pepatch.exe ./cmd/pepatch
```

### 路径处理

```go
// 使用 filepath 包确保跨平台兼容
import "path/filepath"

backupPath := filepath.Join(dir, filename + ".bak")
```

## 未来规划

### 短期目标
- [ ] 完善文档（API参考、贡献指南）
- [ ] 增加测试覆盖率到90%
- [ ] 支持更多PE修改功能（Resource编辑）

### 中期目标
- [ ] GUI版本（基于Web或原生）
- [ ] 插件系统（自定义分析/修改）
- [ ] 批处理模式（处理多个文件）

### 长期目标
- [ ] 支持其他可执行格式（ELF, Mach-O）
- [ ] 云端分析服务
- [ ] 与逆向工程工具集成（IDA, Ghidra）

## 总结

PEPatch的架构设计遵循以下原则：

1. **简洁性优先**：代码清晰胜过聪明技巧
2. **质量门禁**：自动化检查确保代码质量
3. **实用主义**：解决真实问题，不过度设计
4. **可扩展性**：模块化设计，易于添加新功能
5. **零依赖**：完全基于Go标准库

这些原则共同构建了一个可靠、高效、易于维护的PE文件处理工具。
