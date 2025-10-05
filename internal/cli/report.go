// Package cli provides command-line interface utilities.
package cli

import (
	"fmt"
	"strings"

	"github.com/ZacharyZcR/PEPatch/internal/pe"
	"github.com/fatih/color"
)

// Reporter formats and prints PE analysis results.
type Reporter struct {
	info *pe.Info
}

// NewReporter creates a new reporter for the given PE info.
func NewReporter(info *pe.Info) *Reporter {
	return &Reporter{info: info}
}

// Print outputs the complete analysis report.
func (r *Reporter) Print() {
	r.printHeader()
	r.printBasicInfo()
	r.printSections()
	r.printImports()
}

func (r *Reporter) printHeader() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\n╔════════════════════════════════════════╗")
	cyan.Println("║          PEPatch 分析报告              ║")
	cyan.Println("╚════════════════════════════════════════╝")
}

func (r *Reporter) printBasicInfo() {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Println("\n【基本信息】")

	fmt.Printf("  %-20s: %s\n", "文件路径", r.info.FilePath)
	fmt.Printf("  %-20s: %s\n", "文件大小", formatSize(r.info.FileSize))
	fmt.Printf("  %-20s: %s\n", "架构", r.info.Architecture)
	fmt.Printf("  %-20s: %s\n", "子系统", r.info.Subsystem)
	fmt.Printf("  %-20s: 0x%X\n", "入口点", r.info.EntryPoint)
	fmt.Printf("  %-20s: 0x%X\n", "镜像基址", r.info.ImageBase)
}

func (r *Reporter) printSections() {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("\n【节区信息】(共 %d 个)\n", len(r.info.Sections))

	if len(r.info.Sections) == 0 {
		fmt.Println("  未发现节区")
		return
	}

	// Header
	fmt.Println(strings.Repeat("-", 90))
	fmt.Printf("  %-10s %-12s %-15s %-15s %-20s\n",
		"名称", "虚拟地址", "虚拟大小", "原始大小", "特征")
	fmt.Println(strings.Repeat("-", 90))

	// Rows
	for _, section := range r.info.Sections {
		fmt.Printf("  %-10s 0x%08X   %-15s %-15s 0x%08X\n",
			section.Name,
			section.VirtualAddress,
			formatSize(int64(section.VirtualSize)),
			formatSize(int64(section.Size)),
			section.Characteristics,
		)
	}
	fmt.Println(strings.Repeat("-", 90))
}

func (r *Reporter) printImports() {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("\n【导入表】(共 %d 个DLL)\n", len(r.info.Imports))

	if len(r.info.Imports) == 0 {
		fmt.Println("  未发现导入")
		return
	}

	for i, imp := range r.info.Imports {
		green := color.New(color.FgGreen)
		green.Printf("  %3d. %s\n", i+1, imp.DLL)

		if len(imp.Functions) > 0 && imp.Functions[0] != "(symbols not individually listed)" {
			for _, fn := range imp.Functions {
				fmt.Printf("       - %s\n", fn)
			}
		}
	}
	fmt.Println()
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
