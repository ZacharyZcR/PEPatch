// Package main provides the PEPatch CLI tool.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ZacharyZcR/PEPatch/internal/cli"
	"github.com/ZacharyZcR/PEPatch/internal/pe"
	"github.com/fatih/color"
)

var (
	// Analysis flags.
	verbose        = flag.Bool("v", false, "详细模式：显示所有导入/导出函数")
	suspiciousOnly = flag.Bool("s", false, "仅显示可疑节区（RWX权限）")
	detectCaves    = flag.Bool("caves", false, "检测Code Caves（可注入代码的空隙）")
	minCaveSize    = flag.Uint("min-cave-size", 32, "Code Cave最小大小（字节）")
	listImports    = flag.Bool("list-imports", false, "列出详细导入信息（所有函数）")
	analyzeDeps    = flag.Bool("deps", false, "分析依赖关系（递归检测所有DLL依赖）")
	maxDepth       = flag.Uint("max-depth", 3, "依赖分析最大深度（默认: 3）")
	flatList       = flag.Bool("flat", false, "依赖分析使用扁平列表格式（默认: 树状）")

	// Patch flags.
	patchMode     = flag.Bool("patch", false, "修改模式：修改PE文件")
	sectionName   = flag.String("section", "", "要修改的节区名称")
	permissions   = flag.String("perms", "", "新的权限 (例如: R-X, RW-, RWX)")
	entryPoint    = flag.String("entry", "", "新的入口点地址 (十六进制，例如: 0x1000)")
	injectSection = flag.String("inject-section", "", "注入新节区的名称 (最大8字符)")
	sectionSize   = flag.Uint("section-size", 4096, "新节区大小（字节）")
	sectionPerms  = flag.String("section-perms", "RWX", "新节区权限 (R-X, RW-, RWX)")
	addImport     = flag.String("add-import", "", "添加DLL导入 (格式: DLL:Func1,Func2,...)")
	addExport     = flag.String("add-export", "", "添加导出函数（函数名）")
	modifyExport  = flag.String("modify-export", "", "修改导出函数（函数名）")
	removeExport  = flag.String("remove-export", "", "删除导出函数（函数名）")
	exportRVA       = flag.String("export-rva", "", "导出函数RVA地址（十六进制，用于add-export和modify-export）")
	removeSig       = flag.Bool("remove-signature", false, "移除数字签名")
	truncateSig     = flag.Bool("truncate-cert", true, "移除签名时截断证书数据（节省空间）")
	addTLSCallback  = flag.String("add-tls-callback", "", "添加TLS回调函数（RVA地址，十六进制）")
	updateCksum     = flag.Bool("update-checksum", true, "修改后更新校验和")
	createBackup    = flag.Bool("backup", true, "修改前创建备份文件")
)

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	filepath := flag.Arg(0)

	var err error
	if *patchMode {
		err = patchPE(filepath)
	} else {
		err = analyzePE(filepath)
	}

	if err != nil {
		red := color.New(color.FgRed, color.Bold)
		_, _ = red.Fprintf(os.Stderr, "\n错误: %v\n\n", err)
		os.Exit(1)
	}
}

func analyzePE(filepath string) error {
	reader, err := pe.Open(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	analyzer := pe.NewAnalyzer(reader)
	info, err := analyzer.Analyze()
	if err != nil {
		return err
	}

	reporter := cli.NewReporter(info)
	reporter.SetVerbose(*verbose)
	reporter.SetSuspiciousOnly(*suspiciousOnly)
	reporter.Print()

	// Detect code caves if requested.
	if *detectCaves {
		if err := detectCodeCaves(filepath); err != nil {
			return err
		}
	}

	// List detailed imports if requested.
	if *listImports {
		if err := listDetailedImports(filepath); err != nil {
			return err
		}
	}

	// Analyze dependencies if requested.
	if *analyzeDeps {
		if err := analyzeDependencies(filepath); err != nil {
			return err
		}
	}

	return nil
}

func patchPE(filepath string) error {
	if *sectionName == "" && *entryPoint == "" && *injectSection == "" && *addImport == "" &&
		*addExport == "" && *modifyExport == "" && *removeExport == "" && !*removeSig && *addTLSCallback == "" {
		return fmt.Errorf("必须指定至少一个修改操作")
	}

	if err := createBackupIfNeeded(filepath); err != nil {
		return err
	}

	patcher, err := pe.NewPatcher(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = patcher.Close() }()

	if err := applyPatches(patcher); err != nil {
		return err
	}

	printPatchSuccess()
	return nil
}

func applyPatches(patcher *pe.Patcher) error {
	modified := false

	if *sectionName != "" && *permissions != "" {
		if err := patchSectionPerms(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *entryPoint != "" {
		if err := patchEntryPointAddr(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *injectSection != "" {
		if err := injectNewSection(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *addImport != "" {
		if err := addDLLImport(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *addExport != "" {
		if err := addExportFunc(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *modifyExport != "" {
		if err := modifyExportFunc(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *removeExport != "" {
		if err := removeExportFunc(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *removeSig {
		if err := removeSignature(patcher); err != nil {
			return err
		}
		modified = true
	}

	if *addTLSCallback != "" {
		if err := addTLSCallbackFunc(patcher); err != nil {
			return err
		}
		modified = true
	}

	if modified && *updateCksum {
		return updateChecksumWithMessage(patcher)
	}
	return nil
}

func updateChecksumWithMessage(patcher *pe.Patcher) error {
	cyan := color.New(color.FgCyan)
	_, _ = cyan.Println("正在更新PE校验和...")
	return patcher.UpdateChecksum()
}

func createBackupIfNeeded(filepath string) error {
	if !*createBackup {
		return nil
	}

	backupPath := filepath + ".bak"
	if err := copyFile(filepath, backupPath); err != nil {
		return fmt.Errorf("创建备份失败: %w", err)
	}

	green := color.New(color.FgGreen)
	_, _ = green.Printf("✓ 已创建备份: %s\n", backupPath)
	return nil
}

func patchSectionPerms(patcher *pe.Patcher) error {
	read, write, execute, err := parsePermissions(*permissions)
	if err != nil {
		return err
	}

	cyan := color.New(color.FgCyan)
	_, _ = cyan.Printf("正在修改节区 '%s' 的权限...\n", *sectionName)

	return patcher.SetSectionPermissions(*sectionName, read, write, execute)
}

func patchEntryPointAddr(patcher *pe.Patcher) error {
	newEntry, err := parseHexAddress(*entryPoint)
	if err != nil {
		return err
	}

	cyan := color.New(color.FgCyan)

	// Show current entry point
	if currentEntry, err := patcher.GetEntryPoint(); err == nil {
		_, _ = cyan.Printf("当前入口点: 0x%X\n", currentEntry)
	}

	_, _ = cyan.Printf("正在修改入口点为: 0x%X...\n", newEntry)
	return patcher.PatchEntryPoint(newEntry)
}

func parseHexAddress(addr string) (uint32, error) {
	var result uint32
	_, err := fmt.Sscanf(addr, "0x%x", &result)
	if err != nil {
		_, err = fmt.Sscanf(addr, "%x", &result)
		if err != nil {
			return 0, fmt.Errorf("入口点地址格式错误: %s (应为十六进制，例如: 0x1000)", addr)
		}
	}
	return result, nil
}

func injectNewSection(patcher *pe.Patcher) error {
	// Parse permissions.
	read, write, execute, err := parsePermissions(*sectionPerms)
	if err != nil {
		return err
	}

	// Calculate characteristics.
	var characteristics uint32
	if read {
		characteristics |= 0x40000000 // IMAGE_SCN_MEM_READ
	}
	if write {
		characteristics |= 0x80000000 // IMAGE_SCN_MEM_WRITE
	}
	if execute {
		characteristics |= 0x20000000 // IMAGE_SCN_MEM_EXECUTE
		characteristics |= 0x00000020 // IMAGE_SCN_CNT_CODE
	} else {
		characteristics |= 0x00000040 // IMAGE_SCN_CNT_INITIALIZED_DATA
	}

	cyan := color.New(color.FgCyan)
	_, _ = cyan.Printf("正在注入新节区 '%s' (%d 字节, 权限: %s)...\n", *injectSection, *sectionSize, *sectionPerms)

	// Create empty data.
	data := make([]byte, *sectionSize)

	// Extend file size first.
	lastSection := patcher.File().Sections[len(patcher.File().Sections)-1]
	newFileSize := int64(lastSection.Offset + lastSection.Size + uint32(*sectionSize) + 4096)
	if err := patcher.ExtendFileSize(newFileSize); err != nil {
		return err
	}

	// Inject section.
	return patcher.InjectSection(*injectSection, data, characteristics)
}

func addDLLImport(patcher *pe.Patcher) error {
	// Parse format: "DLL:Func1,Func2,Func3"
	parts := strings.SplitN(*addImport, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("导入格式错误，应为 DLL:Func1,Func2")
	}

	dllName := strings.TrimSpace(parts[0])
	if dllName == "" {
		return fmt.Errorf("DLL名称不能为空")
	}

	funcList := strings.Split(parts[1], ",")
	var functions []string
	for _, fn := range funcList {
		fn = strings.TrimSpace(fn)
		if fn != "" {
			functions = append(functions, fn)
		}
	}

	if len(functions) == 0 {
		return fmt.Errorf("必须指定至少一个函数")
	}

	cyan := color.New(color.FgCyan)
	_, _ = cyan.Printf("正在添加导入: %s (%d 个函数)...\n", dllName, len(functions))

	// Extend file size first for new section.
	lastSection := patcher.File().Sections[len(patcher.File().Sections)-1]
	newFileSize := int64(lastSection.Offset + lastSection.Size + 65536) // 64KB buffer
	if err := patcher.ExtendFileSize(newFileSize); err != nil {
		return fmt.Errorf("扩展文件失败: %w", err)
	}

	return patcher.AddImport(dllName, functions)
}

func addExportFunc(patcher *pe.Patcher) error {
	if *exportRVA == "" {
		return fmt.Errorf("添加导出时必须指定 -export-rva")
	}

	rva, err := parseHexAddress(*exportRVA)
	if err != nil {
		return fmt.Errorf("导出RVA地址格式错误: %w", err)
	}

	cyan := color.New(color.FgCyan)
	_, _ = cyan.Printf("正在添加导出函数: %s (RVA: 0x%X)...\n", *addExport, rva)

	modifier := pe.NewExportModifier(patcher)
	return modifier.AddExport(*addExport, rva)
}

func modifyExportFunc(patcher *pe.Patcher) error {
	if *exportRVA == "" {
		return fmt.Errorf("修改导出时必须指定 -export-rva")
	}

	rva, err := parseHexAddress(*exportRVA)
	if err != nil {
		return fmt.Errorf("导出RVA地址格式错误: %w", err)
	}

	cyan := color.New(color.FgCyan)
	_, _ = cyan.Printf("正在修改导出函数: %s (新RVA: 0x%X)...\n", *modifyExport, rva)

	modifier := pe.NewExportModifier(patcher)
	return modifier.ModifyExport(*modifyExport, rva)
}

func removeExportFunc(patcher *pe.Patcher) error {
	cyan := color.New(color.FgCyan)
	_, _ = cyan.Printf("正在删除导出函数: %s...\n", *removeExport)

	modifier := pe.NewExportModifier(patcher)
	return modifier.RemoveExport(*removeExport)
}

func removeSignature(patcher *pe.Patcher) error {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	// Check if signature exists
	remover := pe.NewSignatureRemover(patcher)
	hasSig, offset, size := remover.HasSignature()

	if !hasSig {
		_, _ = yellow.Println("⚠️  文件没有数字签名，跳过移除操作")
		return nil
	}

	_, _ = cyan.Printf("正在移除数字签名 (偏移: 0x%X, 大小: %d 字节)...\n", offset, size)

	if err := remover.RemoveSignature(*truncateSig); err != nil {
		return err
	}

	if *truncateSig {
		_, _ = cyan.Printf("✓ 已移除签名并截断文件\n")
	} else {
		_, _ = cyan.Printf("✓ 已移除签名（保留证书数据）\n")
	}

	return nil
}

func addTLSCallbackFunc(patcher *pe.Patcher) error {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	// Parse callback RVA
	callbackRVA, err := parseHexAddress(*addTLSCallback)
	if err != nil {
		return fmt.Errorf("TLS回调RVA地址格式错误: %w", err)
	}

	// Check if TLS directory exists
	modifier := pe.NewTLSModifier(patcher)
	hasTLS, _, _ := modifier.HasTLS()

	if !hasTLS {
		_, _ = yellow.Println("⚠️  文件没有TLS目录，无法添加TLS回调")
		_, _ = yellow.Println("提示：只有少数PE文件使用TLS，大多数程序不需要TLS回调")
		return fmt.Errorf("文件没有TLS目录")
	}

	_, _ = cyan.Printf("正在添加TLS回调 (RVA: 0x%X)...\n", callbackRVA)

	if err := modifier.AddTLSCallback(callbackRVA); err != nil {
		return err
	}

	_, _ = cyan.Printf("✓ 已成功添加TLS回调\n")
	return nil
}

func printPatchSuccess() {
	green := color.New(color.FgGreen, color.Bold)
	fmt.Println()
	if *sectionName != "" && *permissions != "" {
		_, _ = green.Printf("✓ 成功修改节区权限: %s -> %s\n", *sectionName, *permissions)
	}
	if *entryPoint != "" {
		_, _ = green.Printf("✓ 成功修改入口点: %s\n", *entryPoint)
	}
	if *injectSection != "" {
		_, _ = green.Printf("✓ 成功注入新节区: %s (%d 字节, 权限: %s)\n", *injectSection, *sectionSize, *sectionPerms)
	}
	if *addImport != "" {
		_, _ = green.Printf("✓ 成功添加导入: %s\n", *addImport)
	}
	if *addExport != "" {
		_, _ = green.Printf("✓ 成功添加导出: %s (RVA: %s)\n", *addExport, *exportRVA)
	}
	if *modifyExport != "" {
		_, _ = green.Printf("✓ 成功修改导出: %s (新RVA: %s)\n", *modifyExport, *exportRVA)
	}
	if *removeExport != "" {
		_, _ = green.Printf("✓ 成功删除导出: %s\n", *removeExport)
	}
	if *removeSig {
		_, _ = green.Printf("✓ 成功移除数字签名\n")
	}
	if *addTLSCallback != "" {
		_, _ = green.Printf("✓ 成功添加TLS回调: %s\n", *addTLSCallback)
	}
	fmt.Println()
}

func parsePermissions(perms string) (read, write, execute bool, err error) {
	if len(perms) != 3 {
		return false, false, false, fmt.Errorf("权限格式错误，应为3个字符，例如: R-X, RW-, RWX")
	}

	read = perms[0] == 'R' || perms[0] == 'r'
	write = perms[1] == 'W' || perms[1] == 'w'
	execute = perms[2] == 'X' || perms[2] == 'x'

	return read, write, execute, nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0666)
}

func detectCodeCaves(filepath string) error {
	reader, err := pe.Open(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	detector := pe.NewCodeCaveDetector(reader.RawFile(), reader.File())
	caves, err := detector.FindCodeCaves(uint32(*minCaveSize))
	if err != nil {
		return err
	}

	// Print results.
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	fmt.Println()
	_, _ = cyan.Printf("========== Code Caves (最小 %d 字节) ==========\n", *minCaveSize)

	if len(caves) == 0 {
		_, _ = yellow.Println("未发现符合条件的 Code Caves")
		return nil
	}

	_, _ = green.Printf("发现 %d 个可用 Code Caves:\n\n", len(caves))

	for i, cave := range caves {
		fillPattern := "0x00"
		if cave.FillByte == 0xCC {
			fillPattern = "0xCC (INT3)"
		}

		fmt.Printf("%d. 节区: %s\n", i+1, cave.Section)
		fmt.Printf("   文件偏移: 0x%08X\n", cave.Offset)
		fmt.Printf("   RVA:      0x%08X\n", cave.RVA)
		fmt.Printf("   大小:     %d 字节\n", cave.Size)
		fmt.Printf("   填充:     %s\n", fillPattern)
		fmt.Println()
	}

	return nil
}

func listDetailedImports(filepath string) error {
	reader, err := pe.Open(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	imports, err := pe.ListImportsFromReader(reader)
	if err != nil {
		return err
	}

	// Print results.
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)

	fmt.Println()
	_, _ = cyan.Printf("========== 详细导入表 (%d 个DLL) ==========\n", len(imports))

	for i, imp := range imports {
		_, _ = green.Printf("\n%d. %s (%d 个函数)\n", i+1, imp.DLL, len(imp.Functions))
		for j, fn := range imp.Functions {
			fmt.Printf("   %d. %s\n", j+1, fn)
		}
	}

	fmt.Println()
	return nil
}

func analyzeDependencies(filepath string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	fmt.Println()
	_, _ = cyan.Printf("========== 依赖分析 ==========\n")

	// Analyze dependencies.
	analysis, err := pe.AnalyzeDependencies(filepath, int(*maxDepth))
	if err != nil {
		return fmt.Errorf("依赖分析失败: %w", err)
	}

	if *flatList {
		// Print flat list.
		pe.PrintDependencyList(analysis)
	} else {
		// Print dependency tree.
		_, _ = green.Printf("\n依赖树:\n")
		pe.PrintDependencyTree(analysis.Root, "", false)

		// Print summary.
		fmt.Printf("\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("总计: %d 个依赖\n", analysis.TotalCount)
		fmt.Printf("最大深度: %d\n", analysis.MaxDepth)

		if len(analysis.MissingDeps) > 0 {
			_, _ = red.Printf("\n⚠️  缺失 %d 个依赖:\n", len(analysis.MissingDeps))
			for _, dll := range analysis.MissingDeps {
				_, _ = red.Printf("  - %s\n", dll)
			}
		}
	}

	fmt.Println()
	return nil
}

func printUsage() {
	cyan := color.New(color.FgCyan, color.Bold)
	_, _ = cyan.Println("\nPEPatch - PE文件诊断和修改工具")

	fmt.Println("\n分析模式用法:")
	fmt.Println("  pepatch [选项] <PE文件路径>")
	fmt.Println("\n分析选项:")
	fmt.Println("  -v              详细模式：显示所有导入/导出函数（不限制数量）")
	fmt.Println("  -s              仅显示可疑节区（RWX权限，潜在安全风险）")
	fmt.Println("  -caves          检测Code Caves（可注入代码的空隙）")
	fmt.Println("  -min-cave-size  Code Cave最小大小（字节，默认: 32）")
	fmt.Println("  -list-imports   列出详细导入信息（所有函数，无截断）")
	fmt.Println("  -deps           分析依赖关系（递归检测所有DLL依赖）")
	fmt.Println("  -max-depth      依赖分析最大深度（默认: 3，防止无限递归）")
	fmt.Println("  -flat           依赖分析使用扁平列表格式（默认: 树状）")

	fmt.Println("\n修改模式用法:")
	fmt.Println("  pepatch -patch [选项] <PE文件路径>")
	fmt.Println("\n修改选项:")
	fmt.Println("  -patch                启用修改模式")
	fmt.Println("  -section <名称>       要修改的节区名称（例如: .text, .data）")
	fmt.Println("  -perms <RWX>          新的权限，3个字符：R(读) W(写) X(执行)，用'-'表示无")
	fmt.Println("                        例如: R-X（只读可执行）, RW-（读写）, --X（只执行）")
	fmt.Println("  -entry <地址>         新的入口点地址（十六进制，例如: 0x1000）")
	fmt.Println("  -inject-section <名>  注入新节区的名称（最大8字符）")
	fmt.Println("  -section-size <大小>  新节区大小（字节，默认: 4096）")
	fmt.Println("  -section-perms <RWX>  新节区权限（默认: RWX）")
	fmt.Println("  -add-import <导入>    添加DLL导入（格式: DLL:Func1,Func2,...）")
	fmt.Println("  -add-export <名称>    添加导出函数（需配合 -export-rva）")
	fmt.Println("  -modify-export <名称> 修改导出函数RVA（需配合 -export-rva）")
	fmt.Println("  -remove-export <名称> 删除导出函数")
	fmt.Println("  -export-rva <地址>    导出函数RVA地址（十六进制，例如: 0x1000）")
	fmt.Println("  -remove-signature     移除数字签名")
	fmt.Println("  -truncate-cert        移除签名时截断证书数据（默认: true，节省空间）")
	fmt.Println("  -add-tls-callback <RVA> 添加TLS回调函数（RVA地址，十六进制）")
	fmt.Println("  -backup               修改前创建备份（默认: true）")
	fmt.Println("  -update-checksum      修改后更新校验和（默认: true）")

	fmt.Println("\n示例:")
	fmt.Println("  # 分析文件")
	fmt.Println("  pepatch C:\\Windows\\System32\\notepad.exe")
	fmt.Println("  pepatch -v C:\\Windows\\System32\\kernel32.dll")
	fmt.Println("  pepatch -s suspicious.exe")
	fmt.Println("  pepatch -caves program.exe")
	fmt.Println("  pepatch -caves -min-cave-size 64 program.exe")
	fmt.Println("  pepatch -list-imports program.exe")
	fmt.Println("\n  # 依赖分析")
	fmt.Println("  pepatch -deps program.exe")
	fmt.Println("  pepatch -deps -max-depth 5 program.exe")
	fmt.Println("  pepatch -deps -flat program.exe")

	fmt.Println("\n  # 修改节区权限（安全加固）")
	fmt.Println("  pepatch -patch -section .text -perms R-X program.exe")
	fmt.Println("  pepatch -patch -section .data -perms RW- program.exe")
	fmt.Println("\n  # 修改入口点")
	fmt.Println("  pepatch -patch -entry 0x2000 program.exe")
	fmt.Println("  pepatch -patch -entry 1A40 program.exe")
	fmt.Println("\n  # 注入新节区")
	fmt.Println("  pepatch -patch -inject-section .newsec program.exe")
	fmt.Println("  pepatch -patch -inject-section .code -section-size 8192 -section-perms R-X program.exe")
	fmt.Println("\n  # 添加DLL导入")
	fmt.Println("  pepatch -patch -add-import user32.dll:MessageBoxA,MessageBoxW program.exe")
	fmt.Println("  pepatch -patch -add-import ws2_32.dll:WSAStartup,socket,connect program.exe")
	fmt.Println("\n  # 导出表修改")
	fmt.Println("  pepatch -patch -add-export MyFunction -export-rva 0x1000 mydll.dll")
	fmt.Println("  pepatch -patch -modify-export ExistingFunc -export-rva 0x2000 mydll.dll")
	fmt.Println("  pepatch -patch -remove-export OldFunction mydll.dll")
	fmt.Println("\n  # 数字签名移除")
	fmt.Println("  pepatch -patch -remove-signature program.exe")
	fmt.Println("  pepatch -patch -remove-signature -truncate-cert=false program.exe  # 保留证书数据")
	fmt.Println("\n  # TLS回调注入")
	fmt.Println("  pepatch -patch -add-tls-callback 0x1000 program.exe")
	fmt.Println("\n  # 组合修改")
	fmt.Println("  pepatch -patch -section .text -perms R-X -entry 0x1000 file.exe")
	fmt.Println("  pepatch -patch -entry 0x5000 -backup=false file.exe")
	fmt.Println()
}
