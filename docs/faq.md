# 常见问题

本文档解答PEPatch使用过程中的常见问题。

## 目录

- [安装问题](#安装问题)
- [使用问题](#使用问题)
- [修改问题](#修改问题)
- [导入注入问题](#导入注入问题)
- [技术问题](#技术问题)
- [平台问题](#平台问题)

## 安装问题

### Q: 如何安装PEPatch？

A: 有三种方式：

1. **使用Go安装**（推荐）：
```bash
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest
```

2. **从源码编译**：
```bash
git clone https://github.com/ZacharyZcR/PEPatch.git
cd PEPatch
go build -o pepatch ./cmd/pepatch
```

3. **下载二进制**：
从[Releases页面](https://github.com/ZacharyZcR/PEPatch/releases)下载

### Q: 提示"command not found: pepatch"？

A: 确保Go的bin目录在PATH中：

```bash
# 查看Go bin目录
go env GOPATH

# 添加到PATH（Linux/macOS）
export PATH=$PATH:$(go env GOPATH)/bin

# 添加到PATH（Windows PowerShell）
$env:Path += ";$(go env GOPATH)\bin"
```

永久设置：
- **Linux/macOS**: 添加到 `~/.bashrc` 或 `~/.zshrc`
- **Windows**: 系统设置 → 环境变量 → 编辑PATH

### Q: Go版本要求是什么？

A: Go 1.21或更高版本。检查版本：
```bash
go version
```

## 使用问题

### Q: 如何快速查看PE文件信息？

A: 基础分析无需任何选项：
```bash
pepatch program.exe
```

输出包括：文件信息、PE头、节区、导入/导出摘要。

### Q: 如何查看完整的导入表？

A: 使用`-list-imports`选项：
```bash
pepatch -list-imports program.exe
```

### Q: 如何只看可疑的节区？

A: 使用`-s`选项（suspicious）：
```bash
pepatch -s malware.exe
```

只显示具有RWX权限的节区。

### Q: 什么是Code Cave？如何检测？

A: Code Cave是PE文件中的空白区域（填充0x00或0xCC），可能被用于代码注入。

检测方法：
```bash
# 默认检测32字节以上的cave
pepatch -caves program.exe

# 自定义最小大小
pepatch -caves -min-cave-size 64 program.exe
```

### Q: 输出太长，如何保存到文件？

A: 使用重定向：
```bash
# Linux/macOS/Windows PowerShell
pepatch -v program.exe > report.txt

# 同时显示并保存
pepatch -v program.exe | tee report.txt
```

### Q: 如何批量分析多个文件？

A: 使用shell循环：

**Linux/macOS**：
```bash
for file in *.exe; do
    echo "=== $file ===" >> report.txt
    pepatch "$file" >> report.txt
done
```

**Windows PowerShell**：
```powershell
Get-ChildItem *.exe | ForEach-Object {
    "=== $($_.Name) ===" | Out-File -Append report.txt
    pepatch $_.FullName | Out-File -Append report.txt
}
```

## 修改问题

### Q: 修改PE文件后程序无法运行了？

A: 首先恢复备份：
```bash
# 备份文件是自动创建的
mv program.exe.bak program.exe
```

常见原因：
1. **签名失效**：数字签名在修改后失效，某些程序会拒绝运行
2. **权限错误**：移除了必要的权限（如.text需要执行权限）
3. **校验和不匹配**：某些程序验证校验和

解决方案：
```bash
# 尝试不更新校验和
pepatch -patch -section .text -perms R-X -update-checksum=false program.exe

# 如果是签名问题，需要重新签名（需要证书）
```

### Q: 如何修改节区权限？

A: 使用`-patch -section -perms`：
```bash
# 格式：RWX（R=读, W=写, X=执行, -=无）
pepatch -patch -section .text -perms R-X program.exe    # 只读可执行
pepatch -patch -section .data -perms RW- program.exe    # 读写不执行
pepatch -patch -section .rsrc -perms R-- program.exe    # 只读
```

### Q: 如何修改程序入口点？

A: 使用`-patch -entry`：
```bash
# 十六进制地址（支持有无0x前缀）
pepatch -patch -entry 0x1000 program.exe
pepatch -patch -entry 1A40 program.exe
```

⚠️ **警告**：随意修改入口点会导致程序崩溃，确保目标地址是有效代码。

### Q: 如何注入新节区？

A: 使用`-patch -inject-section`：
```bash
# 默认4096字节，RWX权限
pepatch -patch -inject-section .newsec program.exe

# 自定义大小和权限
pepatch -patch -inject-section .code -section-size 8192 -section-perms R-X program.exe
```

### Q: 不想创建备份文件？

A: 使用`-backup=false`：
```bash
pepatch -patch -section .text -perms R-X -backup=false program.exe
```

⚠️ **不推荐**：强烈建议保留备份。

### Q: 可以同时进行多个修改吗？

A: 可以，多个选项可以组合：
```bash
# 同时修改权限和入口点
pepatch -patch -section .text -perms R-X -entry 0x1000 program.exe

# 注入节区并添加导入
pepatch -patch -inject-section .hook -add-import kernel32.dll:LoadLibraryA program.exe
```

## 导入注入问题

### Q: 导入注入后程序崩溃？

A: 检查以下几点：

1. **DLL是否存在**？
```bash
# Windows
where user32.dll

# Linux（Wine环境）
ls ~/.wine/drive_c/windows/system32/user32.dll
```

2. **函数名是否正确**？
```bash
# 使用dumpbin验证（Visual Studio）
dumpbin /exports C:\Windows\System32\user32.dll | findstr MessageBoxA

# 或使用PEPatch
pepatch -list-imports C:\Windows\System32\user32.dll
```

3. **架构是否匹配**？
```bash
# 检查程序架构
pepatch program.exe | grep "架构"

# 32位程序需要32位DLL，64位程序需要64位DLL
```

### Q: 如何添加导入？

A: 使用`-patch -add-import`：
```bash
# 格式：DLL:Function1,Function2,...
pepatch -patch -add-import user32.dll:MessageBoxA,MessageBoxW program.exe

# 添加多个函数
pepatch -patch -add-import kernel32.dll:Sleep,CreateThread,ExitProcess program.exe
```

### Q: 可以添加多个DLL吗？

A: 目前一次只能添加一个DLL。如需多个，分多次执行：
```bash
pepatch -patch -add-import user32.dll:MessageBoxA program.exe
pepatch -patch -add-import kernel32.dll:Sleep program.exe
```

或通过代码直接调用API多次。

### Q: 支持序号导入吗？

A: 支持！使用`#序号`格式：
```bash
pepatch -patch -add-import user32.dll:#1,#2 program.exe
```

但推荐使用函数名，因为序号可能在不同Windows版本中变化。

### Q: 导入注入的技术原理是什么？

A: PEPatch使用"完整重建导入表 + 保留原始IAT"的方案：
1. 创建新节区（如.newimpt）
2. 重建完整的Import Directory（原始+新增）
3. 原始IAT位置保持不变（避免破坏程序逻辑）
4. 新IAT写入新节区
5. 更新PE头的Import Directory指针

详见：[导入注入技术详解](import-injection.md)

### Q: 导入注入后原有功能会受影响吗？

A: 不会。PEPatch的核心技术确保：
- ✅ 原始IAT位置不变
- ✅ 原始导入函数正常工作
- ✅ 新导入与原有导入共存

### Q: 导入注入后如何验证？

A: 三种方法：

1. **使用PEPatch查看**：
```bash
pepatch -list-imports modified.exe
```

2. **使用dumpbin（Visual Studio）**：
```cmd
dumpbin /imports modified.exe
```

3. **运行程序测试**：
```bash
./modified.exe
# 如果能正常运行，说明注入成功
```

## 技术问题

### Q: PEPatch支持哪些PE格式？

A: 支持：
- ✅ PE32 (32位可执行文件)
- ✅ PE32+ (64位可执行文件)
- ✅ DLL文件
- ✅ SYS文件（驱动程序）

不支持：
- ❌ .NET程序（部分支持，但不推荐）
- ❌ ELF格式（Linux可执行文件）
- ❌ Mach-O格式（macOS可执行文件）

### Q: 如何判断PE文件是32位还是64位？

A: 使用PEPatch查看：
```bash
pepatch program.exe | grep "架构"
```

输出示例：
```
架构: AMD64 (64位)  # 或 i386 (32位)
```

### Q: 熵值有什么作用？

A: 熵值（Entropy）用于检测加壳或加密：
- **熵值 < 6.0**：通常是正常代码或数据
- **熵值 6.0-7.0**：可能是压缩数据
- **熵值 > 7.0**：很可能是加壳或加密

检测示例：
```bash
pepatch suspicious.exe

# 输出示例
.text    执行     熵: 6.42  # 正常
.data    读写     熵: 3.21  # 正常
.rsrc    只读     熵: 7.89  ⚠️ 可疑（可能加密）
```

### Q: 什么是RWX权限？为什么危险？

A: RWX = Read + Write + Execute（可读+可写+可执行）

**危险原因**：
- 允许在运行时修改并执行代码
- 是代码注入攻击的常见目标
- 现代安全实践要求W^X（写或执行，但不能同时）

**安全加固**：
```bash
# 代码段应该是R-X（不可写）
pepatch -patch -section .text -perms R-X program.exe

# 数据段应该是RW-（不可执行）
pepatch -patch -section .data -perms RW- program.exe
```

### Q: TLS回调是什么？

A: TLS (Thread Local Storage) 回调是在主程序入口点之前执行的代码。

**合法用途**：
- 线程初始化
- 全局变量设置

**恶意用途**：
- 反调试技术
- 提前执行恶意代码
- 绕过分析工具

检测方法：
```bash
pepatch program.exe

# 如果有TLS回调，会显示
TLS回调: 1 个回调函数
  - 0x00401000
```

### Q: 数字签名失效有什么影响？

A: 修改PE文件会破坏数字签名，可能导致：
- ✅ 大多数程序仍可运行（签名验证是可选的）
- ⚠️ Windows SmartScreen警告
- ⚠️ 某些程序拒绝运行（如驱动程序）
- ⚠️ 安全软件可能报警

解决方案：
- 开发环境：忽略警告
- 生产环境：使用有效证书重新签名

### Q: 校验和是什么？必须更新吗？

A: PE文件头中的校验和用于验证文件完整性。

**是否必须更新**：
- ✅ 驱动程序（.sys）：必须更新
- ✅ 系统DLL：推荐更新
- ⚠️ 普通EXE：可选（大多数程序不检查）

**更新方法**：
```bash
# 默认会自动更新
pepatch -patch -section .text -perms R-X program.exe

# 禁用更新
pepatch -patch -section .text -perms R-X -update-checksum=false program.exe
```

## 平台问题

### Q: PEPatch能在Linux/macOS上运行吗？

A: 可以！PEPatch本身是跨平台的（用Go编写）。

**安装**：
```bash
# Linux
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest

# macOS
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest
```

**用途**：
- 分析Windows PE文件
- 修改Windows PE文件
- 需要Wine才能运行修改后的Windows程序

### Q: 在Linux上分析Windows程序？

A: 完全可以：
```bash
# Linux上分析Windows程序
pepatch /mnt/c/Windows/System32/notepad.exe

# 通过Samba分析网络共享的文件
pepatch /mnt/smb/share/program.exe
```

### Q: 修改系统文件安全吗？

A: ⚠️ **非常危险！** 不推荐修改系统文件。

如果必须修改：
1. **创建备份**
2. **在虚拟机中测试**
3. **准备系统恢复方案**

```bash
# 分析是安全的（只读）
pepatch C:\Windows\System32\kernel32.dll

# 修改是危险的
# ❌ 不要这样做
pepatch -patch -section .text -perms R-X C:\Windows\System32\kernel32.dll
```

### Q: 支持ARM架构的PE文件吗？

A: 理论支持，但未充分测试。PEPatch主要针对x86/x64架构。

如果需要处理ARM PE文件，欢迎提Issue反馈。

## 错误消息

### Q: "invalid PE file"？

A: 文件不是有效的PE格式。检查：
1. 文件是否损坏
2. 是否确实是PE文件（EXE/DLL）
3. 文件大小是否异常（太小可能不完整）

```bash
# 检查文件头
xxd -l 64 file.exe | head

# 应该看到 "MZ" (0x4D 0x5A) 在开头
```

### Q: "section not found"？

A: 指定的节区不存在。查看可用节区：
```bash
pepatch program.exe

# 查看节区列表
节区 (4):
  .text    ...
  .data    ...
  .rdata   ...
  .rsrc    ...
```

常见拼写错误：
- ❌ `.TEXT` → ✅ `.text`（区分大小写）
- ❌ `text` → ✅ `.text`（需要点号）

### Q: "insufficient space"？

A: 节区空间不足。解决方案：

```bash
# 注入新节区来存放数据
pepatch -patch -inject-section .newdata -section-size 8192 program.exe
```

### Q: "access denied"？

A: 文件权限问题。解决方案：

**Linux/macOS**：
```bash
# 添加写权限
chmod u+w program.exe

# 使用sudo（不推荐，除非必要）
sudo pepatch program.exe
```

**Windows**：
- 右键 → 属性 → 安全 → 编辑权限
- 或以管理员身份运行

## 性能问题

### Q: 处理大文件很慢？

A: PEPatch一次性加载整个文件到内存。优化建议：

1. **对于分析**：通常很快，100MB文件 < 1秒
2. **对于修改**：可能需要几秒（需要重建结构）

如果文件 > 100MB：
- 检查文件是否异常（正常PE文件很少超过100MB）
- 考虑是否是资源（Resource）过大

### Q: 如何加快批处理速度？

A: 使用并行处理：

**Linux/macOS（GNU Parallel）**：
```bash
# 安装
sudo apt install parallel  # Debian/Ubuntu

# 并行处理
parallel pepatch ::: *.exe > report.txt
```

**PowerShell**：
```powershell
Get-ChildItem *.exe | ForEach-Object -Parallel {
    pepatch $_.FullName
} -ThrottleLimit 4
```

## 开发问题

### Q: 如何参与开发？

A: 参见[贡献指南](contributing.md)。

快速开始：
1. Fork项目
2. 创建特性分支
3. 添加功能/修复bug
4. 提交PR

### Q: 如何运行测试？

A:
```bash
# 所有测试
go test -v ./...

# 特定包
go test -v ./internal/pe

# 查看覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Q: 代码质量标准是什么？

A: 严格的复杂度限制：
- 圈复杂度 ≤ 15
- 认知复杂度 ≤ 20

检查：
```bash
golangci-lint run
```

详见：[架构设计 - 代码质量标准](architecture.md#代码质量标准)

### Q: 如何添加新功能？

A: 遵循模块化设计：

1. 在`internal/pe`中添加功能函数
2. 在`cmd/pepatch`中添加CLI接口
3. 添加单元测试
4. 更新文档

示例：
```go
// internal/pe/newfeature.go
func (p *PEPatcher) NewFeature(params) error {
    // 实现
}

// internal/pe/newfeature_test.go
func TestNewFeature(t *testing.T) {
    // 测试
}
```

## 其他问题

### Q: PEPatch是否开源？

A: 是的，采用MIT许可证。

### Q: 可以用于商业项目吗？

A: 可以，MIT许可证允许商业使用。

### Q: 发现Bug如何报告？

A: 在GitHub上提Issue：
https://github.com/ZacharyZcR/PEPatch/issues

包含：
- 详细的问题描述
- 复现步骤
- 系统信息（OS、Go版本、PEPatch版本）
- 错误信息（如有）

### Q: 有没有GUI版本？

A: 目前仅有CLI版本。GUI版本在规划中。

### Q: 支持哪些语言？

A: 目前仅支持中文文档和输出。英文版本在规划中。

### Q: 与其他PE工具相比有什么优势？

**PEPatch优势**：
- ✅ 开源免费（MIT许可证）
- ✅ 跨平台（Linux/macOS/Windows）
- ✅ 零依赖（纯Go实现）
- ✅ 现代化架构（严格的代码质量标准）
- ✅ 强大的导入注入（保留原始IAT）

**其他工具**：
- **CFF Explorer**: GUI友好，但仅Windows
- **PE-bear**: 功能强大，但不支持自动化
- **LordPE**: 经典工具，但年久失修
- **PEview**: 分析优秀，但不支持修改

**PEPatch定位**：自动化、可脚本化、适合CI/CD集成的PE工具。

---

**找不到答案？**

- 提交Issue: https://github.com/ZacharyZcR/PEPatch/issues
- 查看文档: [docs/](README.md)
- 参考示例: [用户指南](user-guide.md)
