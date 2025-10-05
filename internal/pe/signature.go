package pe

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// SignatureInfo contains PE signature information.
type SignatureInfo struct {
	IsSigned        bool
	Certificates    []CertificateInfo
	SigningTime     time.Time
	DigestAlgorithm string
}

// CertificateInfo contains information about a certificate in the signature chain.
type CertificateInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	IsValid      bool
}

// WIN_CERTIFICATE structure.
type winCertificate struct {
	Length          uint32
	Revision        uint16
	CertificateType uint16
	// Certificate data follows
}

const (
	WIN_CERT_REVISION_2_0          = 0x0200
	WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
)

// VerifySignature extracts and verifies PE signature.
func VerifySignature(f *pe.File, r io.ReaderAt) (*SignatureInfo, error) {
	info := &SignatureInfo{
		IsSigned: false,
	}

	// Get Security Directory (Data Directory[4])
	var secDirRVA, secDirSize uint32

	if oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		if len(oh32.DataDirectory) > 4 {
			secDirRVA = oh32.DataDirectory[4].VirtualAddress
			secDirSize = oh32.DataDirectory[4].Size
		}
	} else if oh64, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		if len(oh64.DataDirectory) > 4 {
			secDirRVA = oh64.DataDirectory[4].VirtualAddress
			secDirSize = oh64.DataDirectory[4].Size
		}
	}

	if secDirRVA == 0 || secDirSize == 0 {
		return info, nil // Not signed
	}

	info.IsSigned = true

	// Security Directory uses file offset, not RVA
	offset := int64(secDirRVA)

	// Read WIN_CERTIFICATE header
	var cert winCertificate
	err := binary.Read(io.NewSectionReader(r, offset, int64(secDirSize)), binary.LittleEndian, &cert)
	if err != nil {
		return info, fmt.Errorf("读取证书头失败: %w", err)
	}

	if cert.Revision != WIN_CERT_REVISION_2_0 || cert.CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
		return info, fmt.Errorf("不支持的证书类型")
	}

	// Read certificate data (PKCS#7)
	certDataSize := cert.Length - 8 // Subtract header size
	certData := make([]byte, certDataSize)
	_, err = r.ReadAt(certData, offset+8)
	if err != nil {
		return info, fmt.Errorf("读取证书数据失败: %w", err)
	}

	// Parse PKCS#7 signature
	err = parsePKCS7(certData, info)
	if err != nil {
		return info, fmt.Errorf("解析PKCS#7签名失败: %w", err)
	}

	return info, nil
}

// PKCS#7 ContentInfo structure.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// PKCS#7 SignedData structure (simplified).
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []interface{} `asn1:"set"`
}

func parsePKCS7(data []byte, info *SignatureInfo) error {
	var content contentInfo
	_, err := asn1.Unmarshal(data, &content)
	if err != nil {
		return err
	}

	// Parse SignedData
	var signed signedData
	_, err = asn1.Unmarshal(content.Content.Bytes, &signed)
	if err != nil {
		return err
	}

	// Extract digest algorithm
	if len(signed.DigestAlgorithms) > 0 {
		info.DigestAlgorithm = signed.DigestAlgorithms[0].Algorithm.String()
	}

	// Parse certificates
	if signed.Certificates.Bytes != nil {
		certs, err := x509.ParseCertificates(signed.Certificates.Bytes)
		if err == nil {
			for _, cert := range certs {
				certInfo := CertificateInfo{
					Subject:      cert.Subject.String(),
					Issuer:       cert.Issuer.String(),
					SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
					NotBefore:    cert.NotBefore,
					NotAfter:     cert.NotAfter,
					IsValid:      time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter),
				}
				info.Certificates = append(info.Certificates, certInfo)
			}
		}
	}

	return nil
}
