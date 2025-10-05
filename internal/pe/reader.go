// Package pe provides PE file reading and analysis capabilities.
package pe

import (
	"debug/pe"
	"fmt"
	"os"
)

// Reader wraps debug/pe.File with additional metadata.
type Reader struct {
	file     *pe.File
	rawFile  *os.File
	filepath string
	filesize int64
}

// Open opens a PE file for reading.
func Open(filepath string) (*Reader, error) {
	// Open raw file for export parsing
	rawFile, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("打开PE文件失败: %w", err)
	}

	// Open with debug/pe
	f, err := pe.NewFile(rawFile)
	if err != nil {
		_ = rawFile.Close()
		return nil, fmt.Errorf("解析PE文件失败: %w", err)
	}

	stat, err := rawFile.Stat()
	if err != nil {
		_ = rawFile.Close()
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}

	return &Reader{
		file:     f,
		rawFile:  rawFile,
		filepath: filepath,
		filesize: stat.Size(),
	}, nil
}

// Close closes the underlying PE file.
func (r *Reader) Close() error {
	if r.rawFile != nil {
		_ = r.rawFile.Close()
	}
	return r.file.Close()
}

// RawFile returns the underlying os.File for raw reading.
func (r *Reader) RawFile() *os.File {
	return r.rawFile
}

// File returns the underlying debug/pe.File.
func (r *Reader) File() *pe.File {
	return r.file
}

// FilePath returns the file path.
func (r *Reader) FilePath() string {
	return r.filepath
}

// FileSize returns the file size in bytes.
func (r *Reader) FileSize() int64 {
	return r.filesize
}
