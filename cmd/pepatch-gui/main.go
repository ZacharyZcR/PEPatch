// Package main provides the PEPatch GUI application.
package main

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ZacharyZcR/PEPatch/internal/pe"
)

type guiComponents struct {
	window         fyne.Window
	filePathEntry  *widget.Entry
	analysisOutput *widget.Entry
	statusLabel    *widget.Label
	sectionEntry   *widget.Entry
	permsEntry     *widget.Entry
	entryEntry     *widget.Entry
}

func main() {
	myApp := app.New()
	myApp.Settings().SetTheme(&customTheme{})

	myWindow := myApp.NewWindow("PEPatch - PE文件分析与修改工具")
	myWindow.Resize(fyne.NewSize(1000, 800))

	components := createGUIComponents(myWindow)
	mainContent := createMainLayout(components)

	myWindow.SetContent(mainContent)
	myWindow.ShowAndRun()
}

func createGUIComponents(myWindow fyne.Window) *guiComponents {
	filePathEntry := widget.NewEntry()
	filePathEntry.SetPlaceHolder("选择PE文件...")

	analysisOutput := widget.NewMultiLineEntry()
	analysisOutput.SetPlaceHolder("分析结果将显示在这里...")
	analysisOutput.Disable()

	statusLabel := widget.NewLabel("就绪")

	sectionEntry := widget.NewEntry()
	sectionEntry.SetPlaceHolder(".text")

	permsEntry := widget.NewEntry()
	permsEntry.SetPlaceHolder("R-X")

	entryEntry := widget.NewEntry()
	entryEntry.SetPlaceHolder("0x1000")

	return &guiComponents{
		window:         myWindow,
		filePathEntry:  filePathEntry,
		analysisOutput: analysisOutput,
		statusLabel:    statusLabel,
		sectionEntry:   sectionEntry,
		permsEntry:     permsEntry,
		entryEntry:     entryEntry,
	}
}

func createMainLayout(c *guiComponents) *fyne.Container {
	fileButton := createFilePickerButton(c)
	analyzeButton := createAnalyzeButton(c)
	patchSectionButton := createPatchSectionButton(c)
	patchEntryButton := createPatchEntryButton(c)

	fileBox := container.NewBorder(nil, nil, nil, fileButton, c.filePathEntry)
	analysisBox := container.NewVScroll(c.analysisOutput)
	patchBox := createPatchBox(c, patchSectionButton, patchEntryButton)

	return container.NewBorder(
		container.NewVBox(
			widget.NewLabel("PE文件路径:"),
			fileBox,
			widget.NewSeparator(),
			analyzeButton,
		),
		container.NewVBox(
			widget.NewSeparator(),
			c.statusLabel,
		),
		nil,
		container.NewVBox(
			widget.NewSeparator(),
			patchBox,
		),
		analysisBox,
	)
}

func createFilePickerButton(c *guiComponents) *widget.Button {
	return widget.NewButton("选择文件", func() {
		dialog.ShowFileOpen(func(file fyne.URIReadCloser, err error) {
			if err != nil || file == nil {
				return
			}
			defer func() { _ = file.Close() }()
			c.filePathEntry.SetText(file.URI().Path())
		}, c.window)
	})
}

func createAnalyzeButton(c *guiComponents) *widget.Button {
	return widget.NewButton("分析", func() {
		if c.filePathEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("请先选择PE文件"), c.window)
			return
		}

		c.statusLabel.SetText("正在分析...")
		go func() {
			result, err := analyzePEFile(c.filePathEntry.Text)
			if err != nil {
				dialog.ShowError(err, c.window)
				c.statusLabel.SetText("分析失败")
				return
			}
			c.analysisOutput.SetText(result)
			c.statusLabel.SetText("分析完成")
		}()
	})
}

func createPatchSectionButton(c *guiComponents) *widget.Button {
	return widget.NewButton("修改节区权限", func() {
		if c.filePathEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("请先选择PE文件"), c.window)
			return
		}
		if c.sectionEntry.Text == "" || c.permsEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("请输入节区名称和权限"), c.window)
			return
		}

		c.statusLabel.SetText("正在修改节区权限...")
		go func() {
			err := patchSection(c.filePathEntry.Text, c.sectionEntry.Text, c.permsEntry.Text)
			if err != nil {
				dialog.ShowError(err, c.window)
				c.statusLabel.SetText("修改失败")
				return
			}
			dialog.ShowInformation("成功",
				fmt.Sprintf("成功修改节区 %s 权限为 %s", c.sectionEntry.Text, c.permsEntry.Text), c.window)
			c.statusLabel.SetText("修改完成")
		}()
	})
}

func createPatchEntryButton(c *guiComponents) *widget.Button {
	return widget.NewButton("修改入口点", func() {
		if c.filePathEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("请先选择PE文件"), c.window)
			return
		}
		if c.entryEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("请输入入口点地址"), c.window)
			return
		}

		c.statusLabel.SetText("正在修改入口点...")
		go func() {
			err := patchEntryPoint(c.filePathEntry.Text, c.entryEntry.Text)
			if err != nil {
				dialog.ShowError(err, c.window)
				c.statusLabel.SetText("修改失败")
				return
			}
			dialog.ShowInformation("成功", fmt.Sprintf("成功修改入口点为 %s", c.entryEntry.Text), c.window)
			c.statusLabel.SetText("修改完成")
		}()
	})
}

func createPatchBox(c *guiComponents, patchSectionButton, patchEntryButton *widget.Button) *fyne.Container {
	return container.NewVBox(
		widget.NewLabel("节区权限修改:"),
		container.NewGridWithColumns(3,
			widget.NewLabel("节区名称:"),
			widget.NewLabel("权限:"),
			widget.NewLabel(""),
		),
		container.NewGridWithColumns(3,
			c.sectionEntry,
			c.permsEntry,
			patchSectionButton,
		),
		widget.NewSeparator(),
		widget.NewLabel("入口点修改:"),
		container.NewGridWithColumns(2,
			widget.NewLabel("入口点地址:"),
			widget.NewLabel(""),
		),
		container.NewGridWithColumns(2,
			c.entryEntry,
			patchEntryButton,
		),
	)
}

func analyzePEFile(filepath string) (string, error) {
	reader, err := pe.Open(filepath)
	if err != nil {
		return "", err
	}
	defer func() { _ = reader.Close() }()

	analyzer := pe.NewAnalyzer(reader)
	info, err := analyzer.Analyze()
	if err != nil {
		return "", err
	}

	// Format output
	var output strings.Builder

	// Basic Info
	output.WriteString("========== 基本信息 ==========\n")
	output.WriteString(fmt.Sprintf("文件路径: %s\n", info.FilePath))
	output.WriteString(fmt.Sprintf("文件大小: %d 字节\n", info.FileSize))
	output.WriteString(fmt.Sprintf("架构: %s\n", info.Architecture))
	output.WriteString(fmt.Sprintf("子系统: %s\n", info.Subsystem))
	output.WriteString(fmt.Sprintf("入口点: 0x%X\n", info.EntryPoint))
	output.WriteString(fmt.Sprintf("镜像基址: 0x%X\n", info.ImageBase))

	if info.Checksum != nil {
		output.WriteString("校验和: ")
		if info.Checksum.Valid {
			output.WriteString(fmt.Sprintf("✓ 有效 (0x%08X)\n", info.Checksum.Stored))
		} else {
			output.WriteString(fmt.Sprintf("✗ 无效 (存储: 0x%08X, 计算: 0x%08X)\n",
				info.Checksum.Stored, info.Checksum.Computed))
		}
	}

	// Digital Signature
	if info.Signature != nil {
		output.WriteString("\n========== 数字签名 ==========\n")
		if info.Signature.IsSigned {
			if len(info.Signature.Certificates) > 0 {
				cert := info.Signature.Certificates[0]
				if cert.IsValid {
					output.WriteString(fmt.Sprintf("签名者: ✓ %s\n", cert.Subject))
				} else {
					output.WriteString(fmt.Sprintf("签名者: ✗ %s (已过期)\n", cert.Subject))
				}
				output.WriteString(fmt.Sprintf("颁发者: %s\n", cert.Issuer))
				output.WriteString(fmt.Sprintf("有效期: %s - %s\n",
					cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
			}
		} else {
			output.WriteString("未签名\n")
		}
	}

	// Resources
	if info.Resources != nil && (info.Resources.VersionInfo != nil || info.Resources.HasIcon) {
		output.WriteString("\n========== 资源信息 ==========\n")
		if v := info.Resources.VersionInfo; v != nil {
			if v.FileDescription != "" {
				output.WriteString(fmt.Sprintf("文件描述: %s\n", v.FileDescription))
			}
			if v.FileVersion != "" {
				output.WriteString(fmt.Sprintf("文件版本: %s\n", v.FileVersion))
			}
			if v.ProductName != "" {
				output.WriteString(fmt.Sprintf("产品名称: %s\n", v.ProductName))
			}
			if v.CompanyName != "" {
				output.WriteString(fmt.Sprintf("公司名称: %s\n", v.CompanyName))
			}
		}
		if info.Resources.HasIcon {
			output.WriteString(fmt.Sprintf("图标: 是 (%d 个)\n", info.Resources.IconCount))
		}
	}

	// TLS Callbacks
	if info.TLS != nil && info.TLS.HasTLS && len(info.TLS.Callbacks) > 0 {
		output.WriteString("\n========== TLS 回调 ==========\n")
		output.WriteString(fmt.Sprintf("⚠ 发现 %d 个 TLS 回调函数 (可疑)\n", len(info.TLS.Callbacks)))
		for i, callback := range info.TLS.Callbacks {
			if i >= 5 {
				output.WriteString(fmt.Sprintf("  ... (还有 %d 个回调)\n", len(info.TLS.Callbacks)-5))
				break
			}
			output.WriteString(fmt.Sprintf("  %d. 0x%016X\n", i+1, callback))
		}
	}

	// Relocations
	if info.Relocations != nil && info.Relocations.HasRelocations {
		output.WriteString("\n========== 重定位表 ==========\n")
		output.WriteString("✓ 支持 ASLR (地址空间布局随机化)\n")
		output.WriteString(fmt.Sprintf("重定位块数量: %d\n", info.Relocations.BlockCount))
		output.WriteString(fmt.Sprintf("重定位项总数: %d\n", info.Relocations.TotalEntries))
	}

	// Sections
	output.WriteString(fmt.Sprintf("\n========== 节区信息 (%d 个) ==========\n", len(info.Sections)))
	for _, section := range info.Sections {
		output.WriteString(fmt.Sprintf("  %s:\n", section.Name))
		output.WriteString(fmt.Sprintf("    虚拟地址: 0x%08X\n", section.VirtualAddress))
		output.WriteString(fmt.Sprintf("    虚拟大小: %d 字节\n", section.VirtualSize))
		output.WriteString(fmt.Sprintf("    权限: %s\n", section.Permissions))
		output.WriteString(fmt.Sprintf("    熵值: %.2f\n", section.Entropy))
	}

	// Imports
	output.WriteString(fmt.Sprintf("\n========== 导入表 (%d 个DLL) ==========\n", len(info.Imports)))
	for i, imp := range info.Imports {
		if i >= 20 {
			output.WriteString(fmt.Sprintf("  ... (还有 %d 个DLL)\n", len(info.Imports)-20))
			break
		}
		output.WriteString(fmt.Sprintf("%d. %s (%d 个函数)\n", i+1, imp.DLL, len(imp.Functions)))

		// Show first 5 functions
		maxFuncs := 5
		if len(imp.Functions) > 0 && imp.Functions[0] != "(symbols not individually listed)" {
			for j, fn := range imp.Functions {
				if j >= maxFuncs {
					output.WriteString(fmt.Sprintf("     ... (还有 %d 个函数)\n", len(imp.Functions)-maxFuncs))
					break
				}
				output.WriteString(fmt.Sprintf("     - %s\n", fn))
			}
		}
	}

	// Exports
	if len(info.Exports) > 0 {
		output.WriteString(fmt.Sprintf("\n========== 导出表 (%d 个函数) ==========\n", len(info.Exports)))
		for i, exp := range info.Exports {
			if i >= 20 {
				output.WriteString(fmt.Sprintf("  ... (还有 %d 个函数)\n", len(info.Exports)-20))
				break
			}
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, exp))
		}
	}

	return output.String(), nil
}

func patchSection(filepath, sectionName, perms string) error {
	patcher, err := pe.NewPatcher(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = patcher.Close() }()

	read := strings.Contains(strings.ToUpper(perms), "R")
	write := strings.Contains(strings.ToUpper(perms), "W")
	execute := strings.Contains(strings.ToUpper(perms), "X")

	if err := patcher.SetSectionPermissions(sectionName, read, write, execute); err != nil {
		return err
	}

	return patcher.UpdateChecksum()
}

func patchEntryPoint(filepath, entryStr string) error {
	var entry uint32
	_, err := fmt.Sscanf(entryStr, "0x%x", &entry)
	if err != nil {
		_, err = fmt.Sscanf(entryStr, "%x", &entry)
		if err != nil {
			return fmt.Errorf("入口点地址格式错误")
		}
	}

	patcher, err := pe.NewPatcher(filepath)
	if err != nil {
		return err
	}
	defer func() { _ = patcher.Close() }()

	if err := patcher.PatchEntryPoint(entry); err != nil {
		return err
	}

	return patcher.UpdateChecksum()
}

// customTheme provides high-contrast dark theme for better readability.
type customTheme struct{}

func (t *customTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // Dark background
	case theme.ColorNameButton:
		return color.RGBA{R: 50, G: 120, B: 200, A: 255} // Blue buttons
	case theme.ColorNameDisabled:
		return color.RGBA{R: 100, G: 100, B: 100, A: 255}
	case theme.ColorNameForeground:
		return color.RGBA{R: 240, G: 240, B: 240, A: 255} // Bright white text
	case theme.ColorNameHover:
		return color.RGBA{R: 70, G: 140, B: 220, A: 255}
	case theme.ColorNameInputBackground:
		return color.RGBA{R: 45, G: 45, B: 45, A: 255} // Slightly lighter than background
	case theme.ColorNamePlaceHolder:
		return color.RGBA{R: 150, G: 150, B: 150, A: 255}
	case theme.ColorNamePrimary:
		return color.RGBA{R: 60, G: 150, B: 220, A: 255}
	case theme.ColorNameFocus:
		return color.RGBA{R: 80, G: 160, B: 240, A: 255}
	case theme.ColorNameSelection:
		return color.RGBA{R: 60, G: 120, B: 180, A: 255}
	case theme.ColorNameSuccess:
		return color.RGBA{R: 80, G: 200, B: 120, A: 255}
	case theme.ColorNameWarning:
		return color.RGBA{R: 255, G: 180, B: 50, A: 255}
	case theme.ColorNameError:
		return color.RGBA{R: 230, G: 80, B: 80, A: 255}
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *customTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *customTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *customTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14 // Larger text
	case theme.SizeNameHeadingText:
		return 18
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInlineIcon:
		return 20
	default:
		return theme.DefaultTheme().Size(name)
	}
}
