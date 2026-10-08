//go:build !noadmin

package main

// 默认构建：带上 requireAdministrator 清单，双击弹 UAC 并显示盾牌角标。
// TUN 模式（创建虚拟网卡、改路由表）和安装根证书都需要管理员权限。
import _ "netlens/bindata/admin"
