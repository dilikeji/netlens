//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

// iconResID 是 exe 里图标组的资源 ID。
//
// rsrc 按调用顺序分配 ID：先清单(=1)，再图标组(=2)，然后是各尺寸的图标图(=3..)。
// 所以这里必须是 2，填 0 会退化成 Windows 的默认程序图标。
const iconResID = 2

const (
	windowTitle = "netlens 流量控制台"
	windowW     = 1360
	windowH     = 880
	windowMinW  = 1000
	windowMinH  = 640
)

// runDesktop 打开一个内嵌 WebView2 的窗口，把控制台页面装进去，阻塞到窗口关闭。
//
// 为什么是 WebView2 而不是 Electron/Tauri：Win11 自带 WebView2 运行时，
// 页面代码一行都不用改；而这个绑定是纯 Go 的（还内嵌了 WebView2Loader.dll），
// 所以 `go build` 就能出窗口，既不需要 cgo，也不需要旁边放 DLL。
func runDesktop(webURL, dataDir string, lg *Logger) {
	// Win32 的窗口和消息循环必须待在同一个线程上，而 Go 默认会把 goroutine
	// 在不同 OS 线程之间搬来搬去。不锁的话窗口会建在 A 线程、消息循环跑在 B 线程，
	// 表现是窗口一闪而过或者干脆不响应。
	runtime.LockOSThread()

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		lg.Errorf("创建 WebView2 数据目录失败: %v", err)
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		// 不指定 DataPath 的话，WebView2 会把缓存目录建在 exe 旁边
		//（exe 同级的 xxx.exe.WebView2 文件夹）。又脏，又可能因为目录只读而直接失败。
		DataPath: dataDir,
		WindowOptions: webview2.WindowOptions{
			Title:  windowTitle,
			Width:  windowW,
			Height: windowH,
			IconId: iconResID,
			Center: true,
		},
	})
	if w == nil {
		// 最常见的原因是这台机器没装 WebView2 运行时（Win11 自带，Win10 老版本可能没有）
		lg.Errorf("WebView2 初始化失败：这台机器可能没有 WebView2 运行时")
		messageBox(windowTitle, "WebView2 初始化失败。\n\n"+
			"这台机器可能没有安装 WebView2 运行时（Windows 11 自带）。\n"+
			"将改用系统默认浏览器打开控制台。\n\n"+
			"如需安装运行时：https://developer.microsoft.com/microsoft-edge/webview2/")
		openBrowser(webURL, lg)
		waitForSignal()
		return
	}
	defer w.Destroy()

	w.SetSize(windowMinW, windowMinH, webview2.HintMin)
	w.Navigate(webURL)
	lg.Noticef("桌面窗口已打开，页面地址 %s", webURL)

	w.Run() // 阻塞到窗口被关闭
	lg.Noticef("窗口已关闭")
}

var user32 = syscall.NewLazyDLL("user32.dll")

// messageBox 弹一个系统对话框。
//
// 桌面模式下没有控制台，出错时如果只是往 stdout 写一行，用户看到的就是
// "双击了没反应"。这种时候必须弹个东西出来。
func messageBox(title, text string) {
	const mbOK, mbIconWarning = 0x00000000, 0x00000030
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	_, _, _ = user32.NewProc("MessageBoxW").Call(
		0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), mbOK|mbIconWarning)
}
