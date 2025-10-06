package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DependencyNode represents a node in the dependency tree.
type DependencyNode struct {
	Name         string            // DLL name
	Path         string            // Full path (if found)
	Found        bool              // Whether the DLL was found
	Dependencies []*DependencyNode // Child dependencies
	Depth        int               // Depth in dependency tree
}

// DependencyAnalysis contains the complete dependency analysis result.
type DependencyAnalysis struct {
	Root         *DependencyNode   // Root PE file
	AllDeps      map[string]string // All dependencies: name -> path
	MissingDeps  []string          // List of missing dependencies
	TotalCount   int               // Total number of unique dependencies
	MaxDepth     int               // Maximum dependency depth
	HasCycles    bool              // Whether circular dependencies exist
}

// systemDLLs is a list of well-known Windows system DLLs that we skip recursion for.
var systemDLLs = map[string]bool{
	"kernel32.dll":    true,
	"ntdll.dll":       true,
	"user32.dll":      true,
	"gdi32.dll":       true,
	"advapi32.dll":    true,
	"ws2_32.dll":      true,
	"msvcrt.dll":      true,
	"shell32.dll":     true,
	"ole32.dll":       true,
	"comctl32.dll":    true,
	"comdlg32.dll":    true,
	"oleaut32.dll":    true,
	"shlwapi.dll":     true,
	"wininet.dll":     true,
	"rpcrt4.dll":      true,
	"crypt32.dll":     true,
	"version.dll":     true,
	"winspool.drv":    true,
	"secur32.dll":     true,
	"netapi32.dll":    true,
	"userenv.dll":     true,
	"psapi.dll":       true,
	"iphlpapi.dll":    true,
	"bcrypt.dll":      true,
	"setupapi.dll":    true,
	"cfgmgr32.dll":    true,
	"wintrust.dll":    true,
	"imagehlp.dll":    true,
	"dbghelp.dll":     true,
	"imm32.dll":       true,
	"msimg32.dll":     true,
	"powrprof.dll":    true,
	"uxtheme.dll":     true,
	"dwmapi.dll":      true,
	"api-ms-win-*.dll": true, // API set pattern
}

// AnalyzeDependencies performs a complete dependency analysis of a PE file.
func AnalyzeDependencies(filePath string, maxDepth int) (*DependencyAnalysis, error) {
	analysis := &DependencyAnalysis{
		AllDeps:     make(map[string]string),
		MissingDeps: make([]string, 0),
	}

	// Build dependency tree
	visited := make(map[string]bool)
	root, err := buildDependencyTree(filePath, 0, maxDepth, visited, analysis)
	if err != nil {
		return nil, err
	}

	analysis.Root = root
	analysis.TotalCount = len(analysis.AllDeps)

	return analysis, nil
}

// buildDependencyTree recursively builds the dependency tree.
func buildDependencyTree(filePath string, depth, maxDepth int, visited map[string]bool, analysis *DependencyAnalysis) (*DependencyNode, error) {
	// Get file name
	fileName := filepath.Base(filePath)
	normalizedName := strings.ToLower(fileName)

	// Check if already visited (cycle detection)
	if visited[normalizedName] {
		analysis.HasCycles = true
		return &DependencyNode{
			Name:  fileName,
			Path:  filePath,
			Found: true,
			Depth: depth,
		}, nil
	}

	// Mark as visited
	visited[normalizedName] = true
	defer func() { visited[normalizedName] = false }()

	// Update max depth
	if depth > analysis.MaxDepth {
		analysis.MaxDepth = depth
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return &DependencyNode{
			Name:  fileName,
			Path:  filePath,
			Found: false,
			Depth: depth,
		}, nil
	}

	node := &DependencyNode{
		Name:         fileName,
		Path:         filePath,
		Found:        true,
		Depth:        depth,
		Dependencies: make([]*DependencyNode, 0),
	}

	// Don't recurse too deep
	if depth >= maxDepth {
		return node, nil
	}

	// Parse PE file
	f, err := os.Open(filePath)
	if err != nil {
		return node, nil // File exists but can't open, skip
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		return node, nil // Not a valid PE file, skip
	}
	defer peFile.Close()

	// Get DLL names from import directory
	dllMap, err := getImportedDLLs(peFile, f)
	if err != nil {
		return node, nil // Can't get imports, skip
	}

	// Process each DLL dependency
	baseDir := filepath.Dir(filePath)
	for dllName := range dllMap {
		// Skip system DLLs for recursion (but still record them)
		if isSystemDLL(dllName) {
			analysis.AllDeps[dllName] = "<system>"
			continue
		}

		// Find DLL
		dllPath := findDLL(dllName, baseDir)

		if dllPath == "" {
			// DLL not found
			if !contains(analysis.MissingDeps, dllName) {
				analysis.MissingDeps = append(analysis.MissingDeps, dllName)
			}

			childNode := &DependencyNode{
				Name:  dllName,
				Path:  "",
				Found: false,
				Depth: depth + 1,
			}
			node.Dependencies = append(node.Dependencies, childNode)
		} else {
			// DLL found, recurse
			analysis.AllDeps[dllName] = dllPath

			childNode, err := buildDependencyTree(dllPath, depth+1, maxDepth, visited, analysis)
			if err != nil {
				// Error parsing child, but continue
				childNode = &DependencyNode{
					Name:  dllName,
					Path:  dllPath,
					Found: true,
					Depth: depth + 1,
				}
			}
			node.Dependencies = append(node.Dependencies, childNode)
		}
	}

	return node, nil
}

// findDLL attempts to locate a DLL file using standard Windows search paths.
func findDLL(dllName, baseDir string) string {
	// Normalize name
	if !strings.HasSuffix(strings.ToLower(dllName), ".dll") {
		dllName += ".dll"
	}

	// Search paths in order:
	// 1. Same directory as the executable
	// 2. Windows System32
	// 3. Windows SysWOW64 (for 32-bit on 64-bit)
	// 4. Windows directory
	// 5. Current working directory
	// 6. PATH environment variable

	searchPaths := []string{
		baseDir,
		"C:\\Windows\\System32",
		"C:\\Windows\\SysWOW64",
		"C:\\Windows",
		".",
	}

	// Add PATH directories
	if pathEnv := os.Getenv("PATH"); pathEnv != "" {
		pathDirs := filepath.SplitList(pathEnv)
		searchPaths = append(searchPaths, pathDirs...)
	}

	// Search in each path
	for _, dir := range searchPaths {
		fullPath := filepath.Join(dir, dllName)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	// Also check for Wine paths (for cross-platform analysis)
	if homeDir, err := os.UserHomeDir(); err == nil {
		winePaths := []string{
			filepath.Join(homeDir, ".wine/drive_c/windows/system32", dllName),
			filepath.Join(homeDir, ".wine/drive_c/windows/syswow64", dllName),
		}
		for _, winePath := range winePaths {
			if _, err := os.Stat(winePath); err == nil {
				return winePath
			}
		}
	}

	return ""
}

// isSystemDLL checks if a DLL is a well-known Windows system DLL.
func isSystemDLL(dllName string) bool {
	normalized := strings.ToLower(dllName)

	// Direct match
	if systemDLLs[normalized] {
		return true
	}

	// Pattern match for API sets
	if strings.HasPrefix(normalized, "api-ms-win-") {
		return true
	}
	if strings.HasPrefix(normalized, "ext-ms-") {
		return true
	}

	return false
}

// contains checks if a string slice contains a string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// PrintDependencyTree prints a formatted dependency tree.
func PrintDependencyTree(node *DependencyNode, prefix string, isLast bool) {
	if node == nil {
		return
	}

	// Print current node
	marker := "├── "
	if isLast {
		marker = "└── "
	}
	if node.Depth == 0 {
		marker = ""
	}

	status := ""
	if !node.Found {
		status = " ⚠️ (NOT FOUND)"
	} else if node.Path == "<system>" {
		status = " (system)"
	}

	fmt.Printf("%s%s%s%s\n", prefix, marker, node.Name, status)

	// Prepare prefix for children
	childPrefix := prefix
	if node.Depth > 0 {
		if isLast {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
	}

	// Print children
	for i, child := range node.Dependencies {
		isLastChild := i == len(node.Dependencies)-1
		PrintDependencyTree(child, childPrefix, isLastChild)
	}
}

// PrintDependencyList prints a flat list of all dependencies.
func PrintDependencyList(analysis *DependencyAnalysis) {
	fmt.Printf("\n依赖摘要:\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("总计依赖: %d 个\n", analysis.TotalCount)
	fmt.Printf("最大深度: %d\n", analysis.MaxDepth)
	fmt.Printf("循环依赖: %v\n", analysis.HasCycles)
	fmt.Printf("缺失依赖: %d 个\n\n", len(analysis.MissingDeps))

	if len(analysis.MissingDeps) > 0 {
		fmt.Printf("⚠️  缺失的 DLL:\n")
		for _, dll := range analysis.MissingDeps {
			fmt.Printf("  - %s\n", dll)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("所有依赖:\n")
	for dll, path := range analysis.AllDeps {
		if path == "<system>" {
			fmt.Printf("  ✓ %s (系统DLL)\n", dll)
		} else {
			fmt.Printf("  ✓ %s\n", dll)
			fmt.Printf("    → %s\n", path)
		}
	}
}

// getImportedDLLs extracts DLL names from the import directory.
func getImportedDLLs(peFile *pe.File, r *os.File) (map[string]bool, error) {
	dllMap := make(map[string]bool)

	// Get import directory
	var importDirRVA, importDirSize uint32
	if oh32, ok := peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 1 {
			importDirRVA = oh32.DataDirectory[1].VirtualAddress
			importDirSize = oh32.DataDirectory[1].Size
		}
	} else if oh64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 1 {
			importDirRVA = oh64.DataDirectory[1].VirtualAddress
			importDirSize = oh64.DataDirectory[1].Size
		}
	}

	// No imports
	if importDirRVA == 0 || importDirSize == 0 {
		return dllMap, nil
	}

	// Convert RVA to file offset
	importDirOffset, err := rvaToOffset(peFile, importDirRVA)
	if err != nil {
		return nil, err
	}

	// Read import descriptors
	descriptorSize := 20 // Size of IMAGE_IMPORT_DESCRIPTOR
	for {
		descriptor := make([]byte, descriptorSize)
		_, err := r.ReadAt(descriptor, int64(importDirOffset))
		if err != nil {
			break
		}

		// Check for null descriptor (end of table)
		allZero := true
		for _, b := range descriptor {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			break
		}

		// Read DLL name RVA (offset 12 in descriptor)
		nameRVA := binary.LittleEndian.Uint32(descriptor[12:16])
		if nameRVA == 0 {
			break
		}

		// Convert name RVA to offset
		nameOffset, err := rvaToOffset(peFile, nameRVA)
		if err != nil {
			importDirOffset += uint32(descriptorSize)
			continue
		}

		// Read DLL name
		dllName, err := readCString(r, int64(nameOffset))
		if err != nil {
			importDirOffset += uint32(descriptorSize)
			continue
		}

		if dllName != "" {
			dllMap[strings.ToLower(dllName)] = true
		}

		importDirOffset += uint32(descriptorSize)
	}

	return dllMap, nil
}
