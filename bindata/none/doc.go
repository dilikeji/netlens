// Package none 是个空的占位包。
//
// 它存在的唯一目的：让 `go build -tags noadmin` 时有一个"什么资源都不带"的包可导入，
// 从而编出不要求管理员权限的 exe。真正的清单在隔壁 bindata/admin 里。
package none
