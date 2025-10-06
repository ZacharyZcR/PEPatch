# 导入注入技术详解

本文档深入解析PEPatch的核心技术：**Import Table Injection with IAT Preservation**（保留原始IAT的导入表注入）。

## 目录

- [问题背景](#问题背景)
- [技术挑战](#技术挑战)
- [解决方案演进](#解决方案演进)
- [最终方案详解](#最终方案详解)
- [关键技术细节](#关键技术细节)
- [代码结构](#代码结构)
- [测试验证](#测试验证)

## 问题背景

### 什么是导入表注入？

导入表（Import Table）是PE文件中记录所需DLL及其函数的数据结构。导入表注入是指在PE文件中添加新的DLL导入，使程序加载时自动加载指定DLL和函数。

### 为什么需要导入表注入？

**合法用途**：
- 软件功能扩展（插件系统）
- API Hook实现
- DLL预加载
- 安全研究和逆向工程

**关键需求**：
- ✅ 保留原始IAT位置不变
- ✅ 不破坏程序原有逻辑
- ✅ 支持PE32和PE32+
- ✅ 自动处理对齐和结构更新

## 技术挑战

### 挑战1：IAT位置必须保持不变

**问题**：程序运行时可能通过硬编码偏移访问IAT。

```go
// 错误做法：移动整个IAT
newIAT := append(newImports, originalIAT...)  // ❌ 破坏了IAT地址

// 正确做法：原始IAT原地不动
preserveOriginalIAT()  // ✅ 只添加新条目
```

**影响**：如果移动IAT，程序崩溃率接近100%。

### 挑战2：数据目录更新复杂

PE文件有多个数据目录（Import, Export, Resource等），修改导入表时必须：
1. 更新Import Directory RVA/Size
2. 保持其他目录位置不变
3. 正确处理Bound Import Directory
4. 清理Load Config Directory（避免IAT冲突）

### 挑战3：对齐要求严格

PE文件要求：
- **FileAlignment**：磁盘对齐（通常512或4096字节）
- **SectionAlignment**：内存对齐（通常4096字节）
- **数据结构对齐**：INT/IAT必须以null descriptor结尾

## 解决方案演进

### Solution 1：直接追加（失败）

```go
// 伪代码
newIAT = append(originalIAT, newImports...)
```

**问题**：移动了原始IAT，程序崩溃。

**教训**：IAT位置是神圣不可侵犯的。

### Solution 2：分离IAT（部分成功）

```go
// 伪代码
originalIAT    // 保持位置不变
newSectionIAT  // 新IAT在新节区
```

**问题**：Windows加载器期望单一连续的IAT。

**教训**：必须整合到统一的Import Directory。

### Solution 3：预留空间（失败）

```go
// 伪代码
reservedSpace = allocate(4096)  // 预留空间
if needed {
    writeToReserved()
}
```

**问题**：无法预测需要多少空间，浪费严重。

**教训**：动态扩展才是王道。

### Solution 4：**完整重建导入表**（成功）✅

**核心思想**：
1. 在新节区创建**完整新导入表**（包括原始+新增）
2. 原始IAT **完全保留**在原位
3. 新IAT写入新节区
4. 更新Import Directory指向新表

**为什么成功**：
- ✅ 原始IAT位置不变（满足硬编码访问）
- ✅ 新导入表结构完整（满足加载器要求）
- ✅ 统一管理所有导入（清晰的数据流）

## 最终方案详解

### 架构图

```
原始PE文件：
┌─────────────────────────────────────┐
│ PE Header                           │
├─────────────────────────────────────┤
│ .text (Code)                        │
├─────────────────────────────────────┤
│ .data (Data)                        │
│   ┌──────────────────┐              │
│   │ Original IAT     │ ← 保持不变   │
│   └──────────────────┘              │
├─────────────────────────────────────┤
│ .rdata (Import Descriptors)         │
│   ┌──────────────────┐              │
│   │ INT (Name Table) │              │
│   │ Descriptors      │              │
│   └──────────────────┘              │
└─────────────────────────────────────┘

修改后PE文件：
┌─────────────────────────────────────┐
│ PE Header                           │
│   Import Directory ──────┐          │
├─────────────────────────┼──────────┤
│ .text (Code)            │          │
├─────────────────────────┼──────────┤
│ .data (Data)            │          │
│   ┌──────────────────┐  │          │
│   │ Original IAT     │  │ 位置不变  │
│   └──────────────────┘  │          │
├─────────────────────────┼──────────┤
│ .rdata (旧导入表 - 废弃) │          │
├─────────────────────────┼──────────┤
│ .newimpt (新导入节区) ◄──┘          │
│   ┌──────────────────────────────┐ │
│   │ New Import Descriptors       │ │
│   │  - Original DLL 1 Descriptor │ │
│   │  - Original DLL 2 Descriptor │ │
│   │  - New DLL Descriptor        │ │
│   │  - Null Descriptor           │ │
│   ├──────────────────────────────┤ │
│   │ New INT (Name Table)         │ │
│   │  - Original Functions        │ │
│   │  - New Functions             │ │
│   │  - Null Terminators          │ │
│   ├──────────────────────────────┤ │
│   │ New IAT                      │ │
│   │  - New Import Entries        │ │
│   │  - Null Terminators          │ │
│   ├──────────────────────────────┤ │
│   │ DLL Names                    │ │
│   │ Function Names               │ │
│   └──────────────────────────────┘ │
└─────────────────────────────────────┘
```

### 数据流

```
Step 1: 读取原始导入信息
  ↓
Step 2: 创建新节区 (.newimpt)
  ↓
Step 3: 重建Import Descriptors
  - 复制原始DLL的descriptors
  - 添加新DLL的descriptors
  - 写入Null descriptor
  ↓
Step 4: 重建INT (Import Name Table)
  - 为每个DLL创建INT数组
  - 写入函数名指针
  - 添加Null终止符
  ↓
Step 5: 创建新IAT (Import Address Table)
  - 仅为新导入的DLL创建IAT
  - 原始IAT保持在原位
  - 添加Null终止符
  ↓
Step 6: 写入字符串数据
  - DLL名称
  - 函数名称（带hint）
  ↓
Step 7: 更新PE头
  - Import Directory RVA/Size
  - 清除Load Config Directory
  - 更新节区表
  ↓
Step 8: 更新校验和（可选）
```

### 核心代码逻辑

**关键函数**：`AddImport()` in `internal/pe/import.go`

```go
// 简化版伪代码
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error {
    // 1. 读取原始导入信息
    originalImports := p.parseImports()

    // 2. 创建新节区
    newSection := p.addSection(".newimpt", calculatedSize, RW_PERMS)

    // 3. 计算布局
    descriptorsOffset := 0
    intOffset := descriptorsOffset + descriptorSize
    iatOffset := intOffset + intSize
    stringsOffset := iatOffset + iatSize

    // 4. 写入Import Descriptors
    for _, dll := range originalImports {
        writeDescriptor(dll, originalINT, originalIAT)  // 保留原始IAT
    }
    writeDescriptor(newDLL, newINT, newIAT)  // 新DLL
    writeNullDescriptor()  // 终止符

    // 5. 写入INT（Name Table）
    for _, dll := range allDLLs {
        for _, func := range dll.Functions {
            writePointer(functionNameRVA)
        }
        writeNullTerminator()  // 每个DLL的INT以null结尾
    }

    // 6. 写入新IAT
    for _, func := range newDLL.Functions {
        writePointer(functionNameRVA)
    }
    writeNullTerminator()  // 新IAT以null结尾

    // 7. 写入字符串
    writeDLLNames()
    writeFunctionNames()

    // 8. 更新数据目录
    updateImportDirectory(newSection.VirtualAddress, descriptorSize)
    clearLoadConfigDirectory()  // 避免IAT冲突

    // 9. 更新校验和
    if updateChecksum {
        p.UpdateChecksum()
    }

    return nil
}
```

## 关键技术细节

### 1. Null终止符的重要性

**错误示例**：
```go
// ❌ 忘记写null终止符
for _, func := range functions {
    writeThunk(func)
}
// 加载器不知道在哪里停止，导致访问违例
```

**正确示例**：
```go
// ✅ 每个数组都以null结尾
for _, func := range functions {
    writeThunk(func)
}
writeNullThunk()  // 8字节的0x00（PE32+）或4字节的0x00（PE32）
```

### 2. Load Config Directory清理

**问题**：Load Config Directory可能包含IAT边界信息，与新导入表冲突。

**解决方案**：
```go
// 清除Load Config Directory
dataDir := p.getDataDirectory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
dataDir.VirtualAddress = 0
dataDir.Size = 0
```

**影响**：现代Windows不依赖此目录加载程序，可安全清除。

### 3. 对齐处理

```go
func alignTo(value, alignment uint32) uint32 {
    return (value + alignment - 1) &^ (alignment - 1)
}

// 使用示例
sectionSize := alignTo(rawDataSize, p.FileAlignment)
virtualSize := alignTo(rawDataSize, p.SectionAlignment)
```

### 4. PE32 vs PE32+差异

| 特性 | PE32 (32位) | PE32+ (64位) |
|------|-------------|--------------|
| **Thunk大小** | 4 字节 | 8 字节 |
| **指针大小** | 4 字节 | 8 字节 |
| **Optional Header大小** | 224 字节 | 240 字节 |
| **最大虚拟地址** | 4GB | 理论无限 |

**代码适配**：
```go
if p.Is64Bit {
    thunkSize = 8
    writeUint64(value)
} else {
    thunkSize = 4
    writeUint32(value)
}
```

### 5. RVA计算

**RVA (Relative Virtual Address)** = 内存地址 - ImageBase

```go
// 计算RVA
offset := sectionStart + dataOffset
rva := sectionVirtualAddress + dataOffset

// 在新节区中的偏移
descriptorRVA := newSection.VirtualAddress + 0
intRVA := newSection.VirtualAddress + descriptorSize
iatRVA := newSection.VirtualAddress + descriptorSize + intSize
```

## 代码结构

### 核心文件

**internal/pe/import.go** (23KB) - 最复杂的模块

```go
// 主要函数
func (p *PEPatcher) AddImport(dllName string, funcNames []string) error
func (p *PEPatcher) parseImports() []ImportedDLL
func (p *PEPatcher) buildImportData(...) ([]byte, error)
func (p *PEPatcher) writeImportDescriptors(...) uint32
func (p *PEPatcher) writeImportNameTables(...) uint32
func (p *PEPatcher) writeImportAddressTables(...) uint32
func (p *PEPatcher) writeImportStrings(...) uint32

// 辅助函数
func parseImportDescriptor(data []byte, is64bit bool) ImportDescriptor
func readThunkArray(data []byte, rva uint32, is64bit bool) []uint64
func isOrdinalImport(thunk uint64, is64bit bool) bool
```

### 数据结构

```go
// Import Descriptor (20 bytes)
type ImportDescriptor struct {
    OriginalFirstThunk uint32  // RVA to INT
    TimeDateStamp      uint32  // 通常为0
    ForwarderChain     uint32  // 通常为0
    Name               uint32  // RVA to DLL name
    FirstThunk         uint32  // RVA to IAT
}

// Imported DLL
type ImportedDLL struct {
    Name            string
    Functions       []ImportedFunction
    OriginalINTRVA  uint32  // 原始INT位置
    OriginalIATRVA  uint32  // 原始IAT位置（必须保留）
}

// Imported Function
type ImportedFunction struct {
    Name    string
    Ordinal uint16
    IsOrdinal bool
}
```

## 测试验证

### 单元测试

```bash
# 运行导入注入测试
go test -v ./internal/pe -run TestAddImport

# 测试用例
- TestAddImport_SingleFunction
- TestAddImport_MultipleFunctions
- TestAddImport_DuplicateDLL
- TestAddImport_PE32_and_PE32Plus
- TestAddImport_OrdinalImports
```

### 集成测试

```bash
# 测试真实PE文件
./pepatch -patch -add-import user32.dll:MessageBoxA,MessageBoxW notepad.exe

# 验证步骤
1. 检查程序是否能加载
2. 使用dumpbin验证导入表
3. 运行程序确认功能正常
4. 比较修改前后的IAT地址
```

### 验证工具

**dumpbin（Visual Studio）**：
```cmd
dumpbin /imports modified.exe
```

**PEPatch自身**：
```bash
pepatch -list-imports modified.exe
```

**预期输出**：
```
导入的 DLL (3):

[1] KERNEL32.dll (2 functions)
    - ExitProcess
    - GetModuleHandleW

[2] USER32.dll (2 functions)  ← 新添加
    - MessageBoxA
    - MessageBoxW

[3] msvcrt.dll (1 function)
    - printf
```

## 已知限制

1. **不支持Delay Load Import**
   - 原因：实现复杂度高，实际需求少
   - 解决方案：使用标准导入替代

2. **不支持转发导入（Forwarder）**
   - 原因：需要解析转发链
   - 影响：极少数API受影响

3. **签名失效**
   - 原因：修改PE文件会破坏数字签名
   - 解决方案：修改后重新签名

## 最佳实践

### 1. 测试流程

```bash
# 1. 备份原文件
cp program.exe program.exe.backup

# 2. 分析原始导入
pepatch -list-imports program.exe > original_imports.txt

# 3. 执行注入
pepatch -patch -add-import user32.dll:MessageBoxA program.exe

# 4. 验证新导入
pepatch -list-imports program.exe > new_imports.txt
diff original_imports.txt new_imports.txt

# 5. 测试运行
./program.exe
```

### 2. 错误处理

```go
// 检查DLL是否已存在
if p.isDLLImported(dllName) {
    return fmt.Errorf("DLL %s already imported", dllName)
}

// 检查节区空间
if availableSpace < requiredSpace {
    return fmt.Errorf("insufficient space in section")
}

// 验证函数名
if !isValidFunctionName(funcName) {
    return fmt.Errorf("invalid function name: %s", funcName)
}
```

### 3. 性能优化

- **批量导入**：一次添加多个函数，避免多次重建导入表
- **空间预估**：准确计算所需空间，避免浪费
- **缓存解析**：复用已解析的导入信息

```bash
# ✅ 好：批量添加
pepatch -patch -add-import user32.dll:Func1,Func2,Func3 file.exe

# ❌ 差：多次调用
pepatch -patch -add-import user32.dll:Func1 file.exe
pepatch -patch -add-import user32.dll:Func2 file.exe
pepatch -patch -add-import user32.dll:Func3 file.exe
```

## 参考资料

### 官方文档
- [Microsoft PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE File Import Table Structure](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table)

### 工具
- **dumpbin**: Visual Studio附带的PE分析工具
- **PE-bear**: 开源PE编辑器
- **CFF Explorer**: 高级PE分析工具

### 相关项目
- **PEview**: 经典PE分析工具
- **LordPE**: PE编辑器
- **Stud_PE**: PE结构查看器

## 故障排查案例

### 案例1：程序加载后立即崩溃

**症状**：
```
Exception code: 0xC0000005 (Access Violation)
Fault address: 0x00401234
```

**原因**：忘记添加null终止符到IAT。

**解决方案**：
```go
// 修复前
for _, func := range functions {
    writeThunk(func.RVA)
}

// 修复后
for _, func := range functions {
    writeThunk(func.RVA)
}
writeNullThunk()  // ✅ 添加终止符
```

### 案例2：DLL加载失败

**症状**：
```
Error: The specified module could not be found.
```

**原因**：DLL名称大小写错误或DLL不在系统路径。

**解决方案**：
```bash
# 验证DLL存在
where user32.dll

# 使用正确的大小写
pepatch -patch -add-import USER32.dll:MessageBoxA file.exe
```

### 案例3：IAT地址变化

**症状**：程序功能异常，某些函数调用失败。

**原因**：原始IAT被移动了。

**解决方案**：检查实现逻辑，确保：
```go
// ✅ 保留原始IAT的RVA
descriptor.FirstThunk = originalIATRVA  // 不变

// ❌ 错误：指向新位置
descriptor.FirstThunk = newIATRVA  // 破坏了程序逻辑
```

## 总结

PEPatch的导入注入技术通过**完整重建导入表 + 保留原始IAT**的方案，解决了PE文件导入表注入的核心难题。

**关键成功因素**：
1. ✅ 原始IAT位置不变
2. ✅ 完整重建Import Directory
3. ✅ 正确的null终止符
4. ✅ 清理Load Config Directory
5. ✅ 准确的RVA计算

这项技术已经过大量测试验证，可以安全地应用于PE32和PE32+文件的导入表修改。
