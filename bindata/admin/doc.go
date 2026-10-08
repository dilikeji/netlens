// Package admin 把 Windows 应用程序清单（manifest.syso）链进主程序。
//
// .syso 是 COFF 目标文件，放在包目录里会被链接器自动带上，
// 所以这个包只负责"被导入"，不需要任何代码。
//
// manifest.syso 由仓库根目录的 app.manifest 生成：
//
//	rsrc -manifest app.manifest -o bindata/admin/manifest.syso -arch amd64
//
// 里面写的是 requireAdministrator，因此 exe 双击时会弹 UAC，
// 资源管理器里也会显示盾牌角标。
package admin
