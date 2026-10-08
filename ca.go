package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA 是中间人用的根证书颁发机构。
//
// 它持有根证书与私钥；每遇到一个新的域名，就现场签一张"看起来像"该域名
// 的服务器证书交给 App。App 只要信任了这个根，就会认为自己在和真服务器
// 说话，于是我们的程序就能看到 HTTPS 明文。
type CA struct {
	certPEM []byte
	cert    *x509.Certificate
	key     crypto.Signer

	mu    sync.Mutex
	leafs map[string]*tls.Certificate // 域名 -> 已签发证书，避免重复签名
}

const (
	caCertFile = "netlens-ca.crt"
	caKeyFile  = "netlens-ca.key"
)

// LoadOrCreateCA 从 dir 读取根证书；不存在就生成一份 RSA 2048 的根。
// 用 RSA 而不是 ECDSA 是为了兼容 Windows Schannel / .NET / 老 OpenSSL 客户端。
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 CA 目录失败: %w", err)
	}
	certPath, keyPath := CACertPath(dir), filepath.Join(dir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		ca, err := loadCA(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("加载已有 CA 失败 (%s): %w", certPath, err)
		}
		return ca, nil
	}
	return generateCA(certPath, keyPath)
}

// CACertPath 返回根证书的绝对路径。
func CACertPath(dir string) string { return filepath.Join(dir, caCertFile) }

func generateCA(certPath, keyPath string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成 CA 私钥失败: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "netlens Root CA",
			Organization: []string{"netlens"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("自签名根证书失败: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("解析根证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("序列化 CA 私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("写入根证书失败: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("写入 CA 私钥失败: %w", err)
	}

	return &CA{
		certPEM: certPEM,
		cert:    cert,
		key:     key,
		leafs:   make(map[string]*tls.Certificate),
	}, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("根证书不是有效的 PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("该证书不是 CA 证书")
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("CA 私钥不是有效的 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// 兼容 PKCS#1 (RSA) 与 EC 两种老格式
		if k, e2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); e2 == nil {
			parsed = k
		} else if k, e3 := x509.ParseECPrivateKey(keyBlock.Bytes); e3 == nil {
			parsed = k
		} else {
			return nil, fmt.Errorf("解析 CA 私钥失败: %w", err)
		}
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA 私钥类型 %T 不支持签名", parsed)
	}

	return &CA{
		certPEM: certPEM,
		cert:    cert,
		key:     signer,
		leafs:   make(map[string]*tls.Certificate),
	}, nil
}

// Leaf 返回用于 host 的伪造服务器证书（不区分端口）。
// 结果会被缓存，同一个域名只签一次。
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	host = normalizeHost(host)

	ca.mu.Lock()
	if c, ok := ca.leafs[host]; ok {
		ca.mu.Unlock()
		return c, nil
	}
	ca.mu.Unlock()

	cert, err := ca.sign(host)
	if err != nil {
		return nil, err
	}

	ca.mu.Lock()
	ca.leafs[host] = cert
	ca.mu.Unlock()
	return cert, nil
}

func (ca *CA) sign(host string) (*tls.Certificate, error) {
	// 叶证书用 ECDSA P-256：签名快、体积小，且由 RSA 根签发完全合法。
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}

	notAfter := time.Now().AddDate(1, 0, 0)
	if ca.cert.NotAfter.Before(notAfter) {
		notAfter = ca.cert.NotAfter.Add(-time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"netlens"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("为 %s 签发证书失败: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// 附带根证书，构成完整链发给客户端。
	return &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// CertPEM 返回根证书的 PEM 内容（用于提示用户导入）。
func (ca *CA) CertPEM() []byte { return ca.certPEM }

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "unknown"
	}
	return strings.TrimSuffix(host, ".")
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// caTrusted 判断根证书是否已经装进 Windows 的「受信任的根证书颁发机构」。
//
// 页面上要据此决定是提示"首次运行请先安装根证书"，还是显示"已安装"——
// 提示一直在那儿挂着，用户装完也不会消失，那就成了噪音。
//
// 按 SHA1 指纹比对，而不是按文件名或 CN：同名证书可能有好几张
// （比如换过一次 CA），只看名字会误判成"已安装"。
func caTrusted(dir string) bool {
	pemBytes, err := os.ReadFile(CACertPath(dir))
	if err != nil {
		return false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	sum := sha1.Sum(block.Bytes) //nolint:gosec // 这里只是拿指纹做匹配，不是安全用途
	thumb := hex.EncodeToString(sum[:])

	out, err := exec.Command("certutil", "-store", "ROOT").Output()
	if err != nil {
		return false
	}
	// certutil 输出的指纹是 "ab cd ef …" 这种带空格的十六进制，
	// 前缀文字还随系统语言变，所以把空白全去掉之后只找指纹本身。
	flat := strings.ToLower(strings.Join(strings.Fields(string(out)), ""))
	return strings.Contains(flat, thumb)
}
