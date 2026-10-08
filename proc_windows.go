//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// hideWindow 让子进程不弹出新的控制台窗口。
// 输出仍然通过我们给的管道拿，不受影响。
func hideWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}

// tokenElevation 是 TOKEN_INFORMATION_CLASS 枚举里的 TokenElevation。
const tokenElevation = 20

// isElevated 判断当前进程是否以管理员身份运行。
//
// 为什么要查：mihomo 的 TUN 模式要创建虚拟网卡、改路由表，普通权限下必然失败，
// 而且它报的错很隐晦。界面上先把"你现在是普通权限"这件事讲清楚，
// 比让用户对着 "Access is denied" 猜要省事得多。
func isElevated() bool {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(h, syscall.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer func() { _ = token.Close() }()

	var elevation uint32
	var size uint32
	if err := syscall.GetTokenInformation(token, tokenElevation,
		(*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &size); err != nil {
		return false
	}
	return elevation != 0
}
