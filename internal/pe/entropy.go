package pe

import (
	"io"
	"math"
)

// CalculateEntropy calculates Shannon entropy for a given data block.
// Entropy value ranges from 0 (completely uniform) to 8 (completely random).
// High entropy (>7.0) often indicates encryption or compression (packed malware).
func CalculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy: H = -Σ(p(x) * log2(p(x)))
	var entropy float64
	dataLen := float64(len(data))

	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / dataLen
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// CalculateSectionEntropy reads a section's data and calculates its entropy.
func CalculateSectionEntropy(r io.ReaderAt, offset int64, size uint32) (float64, error) {
	if size == 0 {
		return 0.0, nil
	}

	data := make([]byte, size)
	_, err := r.ReadAt(data, offset)
	if err != nil && err != io.EOF {
		return 0.0, err
	}

	return CalculateEntropy(data), nil
}
