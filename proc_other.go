//go:build !windows

package main

import "syscall"

func hideWindow() *syscall.SysProcAttr { return nil }

// isElevated 在非 Windows 上没有意义，恒为 true。
func isElevated() bool { return true }
