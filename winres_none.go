//go:build noadmin

package main

// 不带清单的构建：go build -tags noadmin -o netlens-noadmin.exe .
// 不弹 UAC，但 TUN 模式和自动安装根证书会失败（页面里会给出提示）。
import _ "netlens/bindata/none"
