# 用户指南

PEPatch是一个强大的PE文件分析和修改工具，本指南将详细介绍所有功能的使用方法。

## 目录

- [安装](#安装)
- [分析模式](#分析模式)
- [修改模式](#修改模式)
- [高级用法](#高级用法)
- [最佳实践](#最佳实践)

## 安装

### 从源码编译

```bash
git clone https://github.com/ZacharyZcR/PEPatch.git
cd PEPatch
make build
```

### 使用Go安装

```bash
go install github.com/ZacharyZcR/PEPatch/cmd/pepatch@latest
```

### 二进制发布

从[Releases页面](https://github.com/ZacharyZcR/PEPatch/releases)下载对应平台的二进制文件。

## 分析模式

### 基础分析

```bash
pepatch program.exe
```

输出包括：
- 文件基本信息（大小、架构、子系统）
- PE头信息（入口点、镜像基址、校验和）
- 数字签名状态
- 版本信息
- 节区信息（名称、大小、权限、熵值）
- 导入/导出表摘要
- TLS回调
- 重定位信息

### 详细模式

```bash
pepatch -v program.exe
```

显示所有导入和导出函数，不限制数量。

### 仅显示可疑节区

```bash
pepatch -s suspicious.exe
```

只显示具有RWX权限的节区（潜在安全风险）。

### Code Cave检测

```bash
# 检测默认大小（32字节）的Code Caves
pepatch -caves program.exe

# 自定义最小大小
pepatch -caves -min-cave-size 64 program.exe
```

Code Cave是PE文件中的空隙区域（填充0x00或0xCC），可用于代码注入。

### 详细导入信息

```bash
pepatch -list-imports program.exe
```

列出所有DLL及其导入的完整函数列表。

### 依赖分析

```bash
# 分析程序依赖关系（显示依赖树）
pepatch -deps program.exe

# 自定义递归深度
pepatch -deps -max-depth 5 program.exe

# 扁平列表格式（显示所有依赖和路径）
pepatch -deps -flat program.exe
```

**依赖分析功能**：
- **递归分析**：自动检测所有DLL依赖（包括间接依赖）
- **依赖树显示**：直观展示依赖关系层次
- **缺失检测**：识别无法找到的DLL
- **路径定位**：显示每个DLL的完整路径
- **循环检测**：检测循环依赖关系

**输出示例**：
```
依赖树:
program.exe
├── user32.dll (system)
├── kernel32.dll (system)
├── customlib.dll
│   ├── msvcrt.dll (system)
│   └── ws2_32.dll (system)
└── helper.dll ⚠️ (NOT FOUND)

总计: 5 个依赖
最大深度: 2
⚠️  缺失 1 个依赖:
  - helper.dll
```

**使用场景**：
- **部署检查**：在部署前验证所有依赖是否齐全
- **故障排查**：快速定位缺失的DLL
- **依赖梳理**：了解程序的完整依赖关系
- **精简打包**：确定需要分发的所有文件

### 组合使用

```bash
# 详细模式 + Code Cave检测
pepatch -v -caves program.exe

# 可疑节区 + 详细导入
pepatch -s -list-imports suspicious.exe
```

## 修改模式

**重要提示**：修改PE文件前会自动创建`.bak`备份文件。

### 节区权限修改

```bash
# 将.text节区设为只读可执行（安全加固）
pepatch -patch -section .text -perms R-X program.exe

# 将.data节区设为读写（移除执行权限）
pepatch -patch -section .data -perms RW- program.exe

# 将.rsrc节区设为只读
pepatch -patch -section .rsrc -perms R-- program.exe
```

权限格式：`RWX`
- `R`: 读权限
- `W`: 写权限
- `X`: 执行权限
- `-`: 无权限

### 入口点修改

```bash
# 十六进制地址（带0x前缀）
pepatch -patch -entry 0x2000 program.exe

# 十六进制地址（无前缀）
pepatch -patch -entry 1A40 program.exe
```

工具会显示修改前后的入口点对比。

### 节区注入

```bash
# 注入默认大小（4096字节）的节区
pepatch -patch -inject-section .newsec program.exe

# 自定义大小和权限
pepatch -patch -inject-section .code -section-size 8192 -section-perms R-X program.exe
```

新节区会被添加到PE文件末尾，并自动更新PE头。

### 导入表注入

**核心功能**：向PE文件添加新的DLL导入，完美保留原始IAT。

```bash
# 添加单个DLL的多个函数
pepatch -patch -add-import user32.dll:MessageBoxA,MessageBoxW program.exe

# 添加网络函数
pepatch -patch -add-import ws2_32.dll:WSAStartup,socket,connect,send,recv program.exe

# 添加系统函数
pepatch -patch -add-import kernel32.dll:Sleep,CreateThread,ExitProcess program.exe
```

格式：`DLL:Func1,Func2,Func3,...`

技术特性：
- ✅ 完整保留原始IAT位置（避免破坏程序逻辑）
- ✅ 支持PE32和PE32+
- ✅ 支持序号导入
- ✅ 自动对齐处理
- ✅ 自动清理Load Config Directory

详细技术说明参见[导入注入技术](import-injection.md)。

### 导出表修改

**核心功能**：修改DLL的导出表，添加、修改或删除导出函数。

```bash
# 添加新的导出函数
pepatch -patch -add-export MyFunction -export-rva 0x1000 mydll.dll

# 修改现有导出函数的RVA
pepatch -patch -modify-export ExistingFunc -export-rva 0x2000 mydll.dll

# 删除导出函数
pepatch -patch -remove-export OldFunction mydll.dll
```

**使用场景**：
- **API重定向**：修改导出函数RVA实现函数Hook
- **功能扩展**：向DLL添加新的导出函数
- **接口清理**：移除废弃的导出函数
- **伪装技术**：修改导出表以改变DLL的表面功能

**技术特性**：
- ✅ 完整重建导出表（Export Directory Table, EDT, ONT）
- ✅ 自动排序函数名（Windows要求按字母序）
- ✅ 支持命名导出和序号导出
- ✅ 自动计算ordinal索引
- ✅ 创建独立的.edata节区

**注意事项**：
- 修改系统DLL可能导致系统不稳定，仅用于测试
- 添加导出时需要确保RVA指向有效代码
- 修改导出会使数字签名失效
- 建议在隔离环境中测试

### 数字签名移除

**核心功能**：移除PE文件的数字签名，可选择是否截断证书数据。

```bash
# 移除签名并截断文件（默认，节省空间）
pepatch -patch -remove-signature program.exe

# 移除签名但保留证书数据（保持文件大小）
pepatch -patch -remove-signature -truncate-cert=false program.exe
```

**使用场景**：
- **修改后失效签名**：修改PE文件后签名自动失效，不如主动移除
- **减小文件体积**：证书数据可能很大（几KB到几百KB）
- **绕过签名检查**：某些程序会拒绝运行签名失效的文件
- **逆向工程准备**：移除签名便于后续修改

**技术特性**：
- ✅ 清除Security Directory（Data Directory[4]）
- ✅ 可选截断文件移除证书数据
- ✅ 支持PE32和PE32+
- ✅ 自动检测签名存在性

**空间节省示例**：
```
原始文件（带签名）: 956 KB
移除签名（截断）:   800 KB  ← 节省156KB
移除签名（不截断）: 956 KB  ← 仅清除目录条目
```

**注意事项**：
- 移除签名后文件将显示为"未签名"
- 某些安全软件可能警告未签名文件
- Windows SmartScreen可能阻止执行
- 系统文件（如驱动）移除签名后无法加载
- **不要在生产系统文件上使用**

**典型工作流**：
```bash
# 1. 分析文件查看签名状态
pepatch program.exe  # 查看【数字签名】部分

# 2. 修改文件（签名会失效）
pepatch -patch -add-import user32.dll:MessageBoxA program.exe

# 3. 移除失效的签名
pepatch -patch -remove-signature program.exe

# 4. 验证签名已移除
pepatch program.exe  # 应显示"未签名"
```

### 组合修改

```bash
# 同时修改权限和入口点
pepatch -patch -section .text -perms R-X -entry 0x1000 file.exe

# 注入节区并添加导入
pepatch -patch -inject-section .hook -add-import kernel32.dll:LoadLibraryA file.exe

# 不创建备份
pepatch -patch -entry 0x5000 -backup=false file.exe

# 不更新校验和
pepatch -patch -section .data -perms RW- -update-checksum=false file.exe
```

## 高级用法

### 批处理分析

```bash
for file in *.exe; do
    echo "Analyzing $file"
    pepatch -s "$file" > "$file.report.txt"
done
```

### 自动化修改脚本

```bash
#!/bin/bash
FILES="app1.exe app2.exe app3.exe"

for file in $FILES; do
    echo "Hardening $file..."
    pepatch -patch -section .text -perms R-X "$file"
    pepatch -patch -section .data -perms RW- "$file"
    echo "Done: $file"
done
```

### 与其他工具配合

```bash
# 分析后用grep过滤可疑特征
pepatch -v suspicious.exe | grep -E "RWX|TLS|0xCC"

# 提取导入表到文件
pepatch -list-imports program.exe > imports.txt

# 检测Code Cave并排序
pepatch -caves program.exe | grep "大小:" | sort -t: -k2 -n
```

## 最佳实践

### 安全分析流程

1. **基础检查**
   ```bash
   pepatch suspicious.exe
   ```
   查看基本信息、签名状态

2. **可疑特征检测**
   ```bash
   pepatch -s suspicious.exe
   ```
   检查RWX节区

3. **深度分析**
   ```bash
   pepatch -v -caves -list-imports suspicious.exe > full-report.txt
   ```
   生成完整报告

4. **TLS回调警告**
   如果发现TLS回调，需额外注意（可能的反调试技术）

### 安全加固流程

1. **分析现状**
   ```bash
   pepatch program.exe
   ```

2. **移除危险权限**
   ```bash
   # .text不应有写权限
   pepatch -patch -section .text -perms R-X program.exe

   # .data不应有执行权限
   pepatch -patch -section .data -perms RW- program.exe
   ```

3. **验证修改**
   ```bash
   pepatch program.exe
   ```
   确认权限已正确修改

4. **测试程序**
   运行程序确保功能正常

### 导入注入最佳实践

1. **确认DLL存在**
   确保目标DLL在系统路径中

2. **验证函数名**
   使用`dumpbin /exports`或类似工具确认函数名正确

3. **测试兼容性**
   ```bash
   # 先备份
   cp program.exe program.exe.original

   # 修改
   pepatch -patch -add-import user32.dll:MessageBoxA program.exe

   # 测试运行
   ./program.exe
   ```

4. **恢复备份**
   如果出现问题：
   ```bash
   mv program.exe.bak program.exe
   ```

## 常见场景

### 场景1：恶意软件分析

```bash
# 完整分析
pepatch -v -caves -list-imports malware.exe > analysis.txt

# 检查可疑特征
grep -E "RWX|TLS|CreateRemoteThread|VirtualAlloc" analysis.txt
```

### 场景2：软件逆向

```bash
# 查找Code Caves（用于补丁注入）
pepatch -caves -min-cave-size 128 target.exe

# 查看导入表（了解功能）
pepatch -list-imports target.exe
```

### 场景3：软件加固

```bash
# 批量加固
for exe in *.exe; do
    echo "Hardening $exe"
    pepatch -patch -section .text -perms R-X "$exe"
    pepatch -patch -section .data -perms RW- "$exe"
done
```

### 场景4：DLL注入准备

```bash
# 1. 检测可用空间
pepatch -caves target.exe

# 2. 注入导入（自动加载DLL）
pepatch -patch -add-import hook.dll:Initialize target.exe
```

### 场景5：部署前依赖检查

```bash
# 1. 分析程序依赖
pepatch -deps myapp.exe

# 2. 检查输出中的缺失DLL
# 如果有 ⚠️ (NOT FOUND)，说明需要打包该DLL

# 3. 使用扁平列表查看所有依赖路径
pepatch -deps -flat myapp.exe > deps_report.txt

# 4. 将非系统DLL复制到部署包
# 根据输出的路径，复制所有需要的自定义DLL

# 5. 在目标环境测试
./myapp.exe
```

**自动化脚本示例**：
```bash
#!/bin/bash
# 自动打包依赖的DLL

APP="myapp.exe"
DIST_DIR="dist"

# 创建分发目录
mkdir -p "$DIST_DIR"
cp "$APP" "$DIST_DIR/"

# 提取非系统依赖
pepatch -deps -flat "$APP" | grep -v "(系统DLL)" | grep "→" | awk '{print $2}' > deps.txt

# 复制依赖
while read -r dll_path; do
    if [ -f "$dll_path" ]; then
        cp "$dll_path" "$DIST_DIR/"
        echo "已复制: $(basename $dll_path)"
    fi
done < deps.txt

echo "部署包已准备就绪: $DIST_DIR"
```

## 故障排查

### 问题：修改后程序无法运行

**解决方案**：
1. 恢复备份：`mv program.exe.bak program.exe`
2. 检查是否误删了必要权限
3. 尝试不更新校验和：`-update-checksum=false`

### 问题：导入注入后程序崩溃

**可能原因**：
1. DLL不存在或路径不正确
2. 函数名拼写错误
3. DLL与程序架构不匹配（32位/64位）

**解决方案**：
1. 确认DLL在系统路径中
2. 使用`dumpbin /exports DLL名`验证函数名
3. 检查程序架构：`pepatch program.exe | grep 架构`

### 问题：权限修改无效

**可能原因**：
1. 程序有签名验证
2. 系统加载器缓存了旧版本

**解决方案**：
1. 重启程序
2. 清除系统缓存
3. 检查是否需要重新签名

## 命令参考

### 分析选项

| 选项 | 说明 | 示例 |
|------|------|------|
| `-v` | 详细模式 | `pepatch -v file.exe` |
| `-s` | 仅显示可疑节区 | `pepatch -s file.exe` |
| `-caves` | 检测Code Caves | `pepatch -caves file.exe` |
| `-min-cave-size` | Cave最小大小 | `pepatch -caves -min-cave-size 64 file.exe` |
| `-list-imports` | 详细导入信息 | `pepatch -list-imports file.exe` |

### 修改选项

| 选项 | 说明 | 示例 |
|------|------|------|
| `-patch` | 启用修改模式 | `pepatch -patch ...` |
| `-section` | 节区名称 | `-section .text` |
| `-perms` | 新权限 | `-perms R-X` |
| `-entry` | 入口点地址 | `-entry 0x1000` |
| `-inject-section` | 注入节区名 | `-inject-section .code` |
| `-section-size` | 节区大小 | `-section-size 8192` |
| `-section-perms` | 节区权限 | `-section-perms RWX` |
| `-add-import` | 添加导入 | `-add-import dll:func1,func2` |
| `-add-export` | 添加导出 | `-add-export MyFunc -export-rva 0x1000` |
| `-modify-export` | 修改导出 | `-modify-export Func -export-rva 0x2000` |
| `-remove-export` | 删除导出 | `-remove-export OldFunc` |
| `-export-rva` | 导出函数RVA | `-export-rva 0x1000` |
| `-remove-signature` | 移除数字签名 | `-remove-signature` |
| `-truncate-cert` | 截断证书数据 | `-truncate-cert=false` |
| `-backup` | 创建备份 | `-backup=false` |
| `-update-checksum` | 更新校验和 | `-update-checksum=false` |

## 下一步

- 了解[架构设计](architecture.md)
- 深入学习[导入注入技术](import-injection.md)
- 参与开发请查看[贡献指南](contributing.md)
