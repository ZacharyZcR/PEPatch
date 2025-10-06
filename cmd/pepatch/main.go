// Package main provides the PEPatch CLI tool.
package main

import (
	"flag"
	"fmt"
	"os"

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

	// Patch flags.
	patchMode    = flag.Bool("patch", false, "修改模式：修改PE文件")
	sectionName  = flag.String("section", "", "要修改的节区名称")
	permissions  = flag.String("perms", "", "新的权限 (例如: R-X, RW-, RWX)")
	entryPoint   = flag.String("entry", "", "新的入口点地址 (十六进制，例如: 0x1000)")
	updateCksum  = flag.Bool("update-checksum", true, "修改后更新校验和")
	createBackup = flag.Bool("backup", true, "修改前创建备份文件")
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

	return nil
}

func patchPE(filepath string) error {
	// Validate parameters
	if *sectionName == "" && *entryPoint == "" {
		return fmt.Errorf("必须指定至少一个修改操作 (-section 或 -entry)")
	}

	// Create backup
	if err := createBackupIfNeeded(filepath); err != nil {
		return err
	}

	// Open patcher
	patcher, err := pe.NewPatcher(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = patcher.Close() }()

	// Apply patches
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

	// Update checksum
	if modified && *updateCksum {
		cyan := color.New(color.FgCyan)
		_, _ = cyan.Println("正在更新PE校验和...")
		if err := patcher.UpdateChecksum(); err != nil {
			return err
		}
	}

	printPatchSuccess()
	return nil
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

func printPatchSuccess() {
	green := color.New(color.FgGreen, color.Bold)
	fmt.Println()
	if *sectionName != "" && *permissions != "" {
		_, _ = green.Printf("✓ 成功修改节区权限: %s -> %s\n", *sectionName, *permissions)
	}
	if *entryPoint != "" {
		_, _ = green.Printf("✓ 成功修改入口点: %s\n", *entryPoint)
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

	fmt.Println("\n修改模式用法:")
	fmt.Println("  pepatch -patch [选项] <PE文件路径>")
	fmt.Println("\n修改选项:")
	fmt.Println("  -patch              启用修改模式")
	fmt.Println("  -section <名称>     要修改的节区名称（例如: .text, .data）")
	fmt.Println("  -perms <RWX>        新的权限，3个字符：R(读) W(写) X(执行)，用'-'表示无")
	fmt.Println("                      例如: R-X（只读可执行）, RW-（读写）, --X（只执行）")
	fmt.Println("  -entry <地址>       新的入口点地址（十六进制，例如: 0x1000）")
	fmt.Println("  -backup             修改前创建备份（默认: true）")
	fmt.Println("  -update-checksum    修改后更新校验和（默认: true）")

	fmt.Println("\n示例:")
	fmt.Println("  # 分析文件")
	fmt.Println("  pepatch C:\\Windows\\System32\\notepad.exe")
	fmt.Println("  pepatch -v C:\\Windows\\System32\\kernel32.dll")
	fmt.Println("  pepatch -s suspicious.exe")
	fmt.Println("  pepatch -caves program.exe")
	fmt.Println("  pepatch -caves -min-cave-size 64 program.exe")

	fmt.Println("\n  # 修改节区权限（安全加固）")
	fmt.Println("  pepatch -patch -section .text -perms R-X program.exe")
	fmt.Println("  pepatch -patch -section .data -perms RW- program.exe")
	fmt.Println("\n  # 修改入口点")
	fmt.Println("  pepatch -patch -entry 0x2000 program.exe")
	fmt.Println("  pepatch -patch -entry 1A40 program.exe")
	fmt.Println("\n  # 组合修改")
	fmt.Println("  pepatch -patch -section .text -perms R-X -entry 0x1000 file.exe")
	fmt.Println("  pepatch -patch -entry 0x5000 -backup=false file.exe")
	fmt.Println()
}
