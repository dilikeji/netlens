//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// Windows 控制台默认用 GBK 代码页，且不认识 ANSI 转义序列。
// 不处理的话，日志里的中文会变成乱码，颜色会显示成 "←[36m" 这样的字面量。
// 这里直接调 kernel32 把控制台切成 UTF-8 并打开虚拟终端处理。
var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle       = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
)

const (
	stdOutputHandle                 = ^uintptr(10) // -11
	enableVirtualTerminalProcessing = 0x0004
	utf8CodePage                    = 65001
)

func setupConsole() {
	_, _, _ = procSetConsoleOutputCP.Call(utf8CodePage)

	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if h == 0 || h == ^uintptr(0) {
		return
	}
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	_, _, _ = procSetConsoleMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing))
}
