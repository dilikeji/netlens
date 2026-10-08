//go:build !windows

package main

// runDesktop 在非 Windows 上没有实现：WebView2 是 Windows 专有的。
// 退回到"用系统浏览器打开 + 等退出信号"，行为与 -no-window 一致。
func runDesktop(webURL, dataDir string, lg *Logger) {
	lg.Errorf("桌面窗口仅支持 Windows，改用浏览器打开 %s", webURL)
	openBrowser(webURL, lg)
	waitForSignal()
}

func messageBox(title, text string) {
	lg := NewLogger(false, LogNormal)
	lg.Errorf("%s: %s", title, text)
}
