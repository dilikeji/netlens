package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Blob 是"可能是文本、也可能是二进制"的一段字节。
//
// 它在 JSON 里的形态：
//
//	文本 → {"binary":false,"text":"...","len":123}
//	二进制 → {"binary":true,"b64":"...","len":123}
//
// 这样前端不需要额外判断就能安全渲染中文，也不会因为非法 UTF-8
// 把整个 JSON 编码搞挂（json.Marshal 遇到 []byte 会直接 base64，
// 但那样前端就拿不到可读文本了）。
type Blob struct {
	Data []byte
}

type blobJSON struct {
	Binary bool   `json:"binary"`
	Text   string `json:"text,omitempty"`
	B64    string `json:"b64,omitempty"`
	Len    int    `json:"len"`
}

func (b Blob) MarshalJSON() ([]byte, error) {
	o := blobJSON{Binary: false, Len: len(b.Data)}
	switch {
	case len(b.Data) == 0:
	case looksTextual(b.Data):
		o.Text = string(b.Data)
	default:
		o.Binary = true
		o.B64 = base64.StdEncoding.EncodeToString(b.Data)
	}
	return json.Marshal(o)
}

func (b *Blob) UnmarshalJSON(data []byte) error {
	var o blobJSON
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	if o.Binary || (o.B64 != "" && o.Text == "") {
		d, err := base64.StdEncoding.DecodeString(o.B64)
		if err != nil {
			return fmt.Errorf("base64 解码失败: %w", err)
		}
		b.Data = d
		return nil
	}
	b.Data = []byte(o.Text)
	return nil
}

// ---------------------------------------------------------------- 编解码工具

// decodeBody 按 Content-Encoding 解压，返回解码后的内容与是否解压过。
// 失败时原样返回——不能让"看日志"这件事把请求搞挂。
func decodeBody(data []byte, contentEncoding string) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip", "x-gzip":
		if dec, err := gunzip(data); err == nil {
			return dec, true
		}
	case "deflate":
		if dec, err := inflate(data); err == nil {
			return dec, true
		}
	}
	return data, false
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(io.LimitReader(r, 8<<20))
}

func inflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer func() { _ = r.Close() }()
	return io.ReadAll(io.LimitReader(r, 8<<20))
}

// ---------------------------------------------------------------- 文件判定

// FileInfo 表示"这段 body 是个文件"，页面只显示类型和大小，不展示内容。
//
// 为什么不把内容也发过去：一张 500KB 的图打成 base64 是 680KB，
// 塞进 JSON 推给页面纯属浪费——而页面对它要做的只是说一句"这是个图片"。
type FileInfo struct {
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
}

// mediaType 去掉 Content-Type 里的参数，只留主类型。
func mediaType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// isTextualMedia 判断某个 Content-Type 是不是"能当文本看"的。
func isTextualMedia(ct string) bool {
	switch {
	case strings.HasPrefix(ct, "text/"):
		return true
	case strings.HasSuffix(ct, "+json"), strings.HasSuffix(ct, "+xml"):
		return true // 含 image/svg+xml：它本身就是文本，能读
	}
	switch ct {
	case "application/json", "application/xml", "application/javascript",
		"application/x-javascript", "application/ecmascript", "application/graphql",
		"application/x-www-form-urlencoded", "application/x-ndjson", "application/ld+json":
		return true
	}
	return false
}

// looksLikeFile 判断这段内容是不是"文件"（图片/音视频/压缩包/二进制流…），
// 而不是可以直接读的文本。
//
// 有 Content-Type 就以它为准，没有才退回去看字节——两条都要，
// 因为抓包遇到的响应里两个都不可靠。
func looksLikeFile(data []byte, contentType string) bool {
	if ct := mediaType(contentType); ct != "" {
		return !isTextualMedia(ct)
	}
	return !looksTextual(data)
}

// fileInfoOf 返回 nil 表示"这不是文件，正常展示内容"。
func fileInfoOf(contentType string, data []byte, total int64) *FileInfo {
	if total <= 0 {
		return nil
	}
	if !looksLikeFile(data, contentType) {
		return nil
	}
	return &FileInfo{ContentType: mediaType(contentType), Size: total}
}

// classifyBody 是"这个 body 该当文本看还是当一个文件"的唯一判定入口。
//
// 先按 Content-Encoding 解压再判断：gzip 之后是二进制，但内容是 JSON，
// 直接看压缩后的字节会把所有带压缩的接口都误判成文件。
func classifyBody(data []byte, contentType, contentEncoding string, total int64) *FileInfo {
	decoded := data
	if contentEncoding != "" {
		if d, ok := decodeBody(data, contentEncoding); ok {
			decoded = d
		}
	}
	return fileInfoOf(contentType, decoded, total)
}

// looksTextual 用一个宽松的启发式判断"这段字节能不能当文本显示"。
func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	ctrl := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if c < 0x20 {
			ctrl++
		}
	}
	return ctrl*20 <= len(b)
}

// tryPrettyJSON 是 JSON 就格式化，不是就原样返回。
func tryPrettyJSON(b []byte) (string, bool) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return "", false
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, trimmed, "", "  "); err != nil {
		return "", false
	}
	return buf.String(), true
}

// hexDump 生成十六进制 + ASCII 的经典 dump。
func hexDump(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]
		fmt.Fprintf(&sb, "%08x  %-47s  |%s|\n", i, hex.EncodeToString(chunk), printable(chunk))
	}
	return sb.String()
}

func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.2f MB", float64(n)/(1024*1024))
	}
}

// bodyCapture 只保留前 max 字节，但统计总长度。
//
// max == 0 表示"只计数、不保留内容"——用于已经确定是文件的 body：
// 记录仓库是全局共享内存预算的，把图片视频抓回来只会把有用的文本记录挤掉。
type bodyCapture struct {
	max       int
	buf       bytes.Buffer
	total     int64
	truncated bool
}

func newBodyCapture(max int) *bodyCapture {
	if max < 0 {
		max = 512 * 1024
	}
	return &bodyCapture{max: max}
}

func (c *bodyCapture) Write(p []byte) (int, error) {
	n := len(p)
	c.total += int64(n)
	if c.max == 0 {
		return n, nil
	}
	if room := c.max - c.buf.Len(); room > 0 {
		if room > n {
			room = n
		}
		c.buf.Write(p[:room])
		if room < n {
			c.truncated = true
		}
	} else {
		c.truncated = true
	}
	return n, nil
}

func (c *bodyCapture) Bytes() []byte { return c.buf.Bytes() }
func (c *bodyCapture) Len() int      { return c.buf.Len() }
func (c *bodyCapture) Total() int64  { return c.total }
func (c *bodyCapture) Blob() Blob    { return Blob{Data: append([]byte(nil), c.buf.Bytes()...)} }
