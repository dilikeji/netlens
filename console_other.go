//go:build !windows

package main

// 非 Windows 平台不需要处理控制台代码页。
func setupConsole() {}
