//go:build windows

// windowcheck 是个很小的排查工具：列出进程的顶层可见窗口，以及窗口里嵌的子控件类名。
//
// 为什么需要它：桌面版双击之后既没有控制台也没法截图，
// 而"窗口建起来了"和"WebView2 真的嵌进去了"是两件事——
// 前者只说明 Win32 窗口存在，后者要看窗口里有没有 Chrome_WidgetWin 之类的子控件。
//
//	go run ./tools/windowcheck -pid 12345
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	user32                       = syscall.NewLazyDLL("user32.dll")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procEnumChildWindows         = user32.NewProc("EnumChildWindows")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetClassNameW            = user32.NewProc("GetClassNameW")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procGetWindowThreadProcessID = user32.NewProc("GetWindowThreadProcessId")
)

func textOf(proc *syscall.LazyProc, hwnd uintptr, n int) string {
	buf := make([]uint16, n)
	got, _, _ := proc.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(n))
	if got == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func main() {
	pid := flag.Int("pid", 0, "只看这个进程；0 = 列出所有可见窗口")
	children := flag.Bool("children", true, "同时列出窗口内的子控件类名")
	flag.Parse()

	found := 0
	enum := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var wpid uint32
		procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&wpid)))
		if *pid != 0 && int(wpid) != *pid {
			return 1
		}
		if visible, _, _ := procIsWindowVisible.Call(hwnd); visible == 0 {
			return 1
		}
		title := textOf(procGetWindowTextW, hwnd, 512)
		if title == "" {
			return 1
		}
		fmt.Printf("window pid=%d hwnd=0x%x class=%s title=%q\n",
			wpid, hwnd, textOf(procGetClassNameW, hwnd, 256), title)
		found++

		if *children {
			childEnum := syscall.NewCallback(func(child uintptr, _ uintptr) uintptr {
				cls := textOf(procGetClassNameW, child, 256)
				if cls != "" {
					fmt.Printf("  child class=%s\n", cls)
				}
				return 1
			})
			procEnumChildWindows.Call(hwnd, childEnum, 0)
		}
		return 1
	})
	procEnumWindows.Call(enum, 0)

	if found == 0 {
		fmt.Println("(没有找到可见窗口)")
		os.Exit(1)
	}
}
