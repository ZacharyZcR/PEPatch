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
	verbose        = flag.Bool("v", false, "详细模式：显示所有导入/导出函数")
	suspiciousOnly = flag.Bool("s", false, "仅显示可疑节区（RWX权限）")
)

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	filepath := flag.Arg(0)

	if err := analyzePE(filepath); err != nil {
		red := color.New(color.FgRed, color.Bold)
		red.Fprintf(os.Stderr, "\n错误: %v\n\n", err)
		os.Exit(1)
	}
}

func analyzePE(filepath string) error {
	reader, err := pe.Open(filepath)
	if err != nil {
		return err
	}
	defer reader.Close()

	analyzer := pe.NewAnalyzer(reader)
	info, err := analyzer.Analyze()
	if err != nil {
		return err
	}

	reporter := cli.NewReporter(info)
	reporter.SetVerbose(*verbose)
	reporter.SetSuspiciousOnly(*suspiciousOnly)
	reporter.Print()

	return nil
}

func printUsage() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\nPEPatch - PE文件诊断工具")
	fmt.Println("\n用法:")
	fmt.Println("  pepatch [选项] <PE文件路径>")
	fmt.Println("\n选项:")
	fmt.Println("  -v    详细模式：显示所有导入/导出函数（不限制数量）")
	fmt.Println("  -s    仅显示可疑节区（RWX权限，潜在安全风险）")
	fmt.Println("\n示例:")
	fmt.Println("  pepatch C:\\Windows\\System32\\notepad.exe")
	fmt.Println("  pepatch -v C:\\Windows\\System32\\kernel32.dll")
	fmt.Println("  pepatch -s suspicious.exe")
	fmt.Println()
}
