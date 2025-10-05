// Package main provides the PEPatch GUI application.
package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
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
	myWindow := myApp.NewWindow("PEPatch - PE文件分析与修改工具")
	myWindow.Resize(fyne.NewSize(900, 700))

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
	output.WriteString(fmt.Sprintf("文件路径: %s\n", info.FilePath))
	output.WriteString(fmt.Sprintf("文件大小: %d 字节\n", info.FileSize))
	output.WriteString(fmt.Sprintf("架构: %s\n", info.Architecture))
	output.WriteString(fmt.Sprintf("子系统: %s\n", info.Subsystem))
	output.WriteString(fmt.Sprintf("入口点: 0x%X\n", info.EntryPoint))
	output.WriteString(fmt.Sprintf("镜像基址: 0x%X\n", info.ImageBase))

	if info.Checksum != nil {
		if info.Checksum.Valid {
			output.WriteString(fmt.Sprintf("校验和: ✓ 有效 (0x%08X)\n", info.Checksum.Stored))
		} else {
			output.WriteString(fmt.Sprintf("校验和: ✗ 无效 (存储: 0x%08X, 计算: 0x%08X)\n",
				info.Checksum.Stored, info.Checksum.Computed))
		}
	}

	output.WriteString(fmt.Sprintf("\n节区信息 (%d 个):\n", len(info.Sections)))
	for _, section := range info.Sections {
		output.WriteString(fmt.Sprintf("  %s: 权限=%s, 熵值=%.2f\n",
			section.Name, section.Permissions, section.Entropy))
	}

	output.WriteString(fmt.Sprintf("\n导入表 (%d 个DLL):\n", len(info.Imports)))
	for i, imp := range info.Imports {
		if i >= 10 {
			output.WriteString(fmt.Sprintf("  ... (还有 %d 个DLL)\n", len(info.Imports)-10))
			break
		}
		output.WriteString(fmt.Sprintf("  %s (%d 个函数)\n", imp.DLL, len(imp.Functions)))
	}

	output.WriteString(fmt.Sprintf("\n导出表 (%d 个函数)\n", len(info.Exports)))

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
