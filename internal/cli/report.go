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
	r.printExports()
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
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("  %-10s %-12s %-15s %-15s %-8s %-20s\n",
		"名称", "虚拟地址", "虚拟大小", "原始大小", "权限", "特征")
	fmt.Println(strings.Repeat("-", 100))

	// Rows
	for _, section := range r.info.Sections {
		// Highlight dangerous permissions (RWX)
		permColor := color.New(color.FgWhite)
		if section.Permissions == "RWX" {
			permColor = color.New(color.FgRed, color.Bold)
		} else if strings.Contains(section.Permissions, "X") {
			permColor = color.New(color.FgYellow)
		}

		fmt.Printf("  %-10s 0x%08X   %-15s %-15s ",
			section.Name,
			section.VirtualAddress,
			formatSize(int64(section.VirtualSize)),
			formatSize(int64(section.Size)),
		)
		permColor.Printf("%-8s", section.Permissions)
		fmt.Printf(" 0x%08X\n", section.Characteristics)
	}
	fmt.Println(strings.Repeat("-", 100))
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
		funcCount := len(imp.Functions)
		green.Printf("  %3d. %s (%d 个函数)\n", i+1, imp.DLL, funcCount)

		if funcCount > 0 && imp.Functions[0] != "(symbols not individually listed)" {
			const maxDisplay = 10
			displayCount := funcCount
			if displayCount > maxDisplay {
				displayCount = maxDisplay
			}

			for j := 0; j < displayCount; j++ {
				fmt.Printf("       - %s\n", imp.Functions[j])
			}

			if funcCount > maxDisplay {
				gray := color.New(color.FgHiBlack)
				gray.Printf("       ... (还有 %d 个函数)\n", funcCount-maxDisplay)
			}
		}
	}
	fmt.Println()
}

func (r *Reporter) printExports() {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("\n【导出表】(共 %d 个函数)\n", len(r.info.Exports))

	if len(r.info.Exports) == 0 {
		fmt.Println("  未发现导出")
		return
	}

	const maxDisplay = 20
	displayCount := len(r.info.Exports)
	if displayCount > maxDisplay {
		displayCount = maxDisplay
	}

	for i := 0; i < displayCount; i++ {
		green := color.New(color.FgGreen)
		green.Printf("  %3d. %s\n", i+1, r.info.Exports[i])
	}

	if len(r.info.Exports) > maxDisplay {
		gray := color.New(color.FgHiBlack)
		gray.Printf("  ... (还有 %d 个函数)\n", len(r.info.Exports)-maxDisplay)
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
