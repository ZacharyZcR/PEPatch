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
	filepath string
	filesize int64
}

// Open opens a PE file for reading.
func Open(filepath string) (*Reader, error) {
	f, err := pe.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("打开PE文件失败: %w", err)
	}

	stat, err := os.Stat(filepath)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}

	return &Reader{
		file:     f,
		filepath: filepath,
		filesize: stat.Size(),
	}, nil
}

// Close closes the underlying PE file.
func (r *Reader) Close() error {
	return r.file.Close()
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
