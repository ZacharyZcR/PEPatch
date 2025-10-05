// Package main provides the PEPatch CLI tool.
package main

import (
	"fmt"
	"os"

	"github.com/ZacharyZcR/PEPatch/internal/cli"
	"github.com/ZacharyZcR/PEPatch/internal/pe"
	"github.com/fatih/color"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	filepath := os.Args[1]

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
	reporter.Print()

	return nil
}

func printUsage() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\nPEPatch - PE文件诊断工具")
	fmt.Println("\n用法:")
	fmt.Println("  pepatch <PE文件路径>")
	fmt.Println("\n示例:")
	fmt.Println("  pepatch C:\\Windows\\System32\\notepad.exe")
	fmt.Println()
}
