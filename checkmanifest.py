"""校验 exe 的 PE 属性：子系统类型、应用程序清单、图标资源。

为什么需要单独校验：这几样东西放错了都不会有任何报错提示，
表现只是"双击还是弹控制台"、"图标是空白方块"、"不弹 UAC"，
很容易以为是自己写对了。而且在二进制里 grep 到字符串也不算数——
那可能只是别处的巧合，必须真的顺着 PE 的资源目录读出来。

用法：
    python checkmanifest.py netlens.exe
    python checkmanifest.py netlens.exe netlens-noadmin.exe
"""
import struct
import sys

RT_ICON = 3
RT_GROUP_ICON = 14
RT_MANIFEST = 24

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI（双击不弹控制台窗口）",
    3: "Windows Console（会弹控制台）",
}


def parse(path):
    with open(path, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ":
        raise ValueError("不是 PE 文件")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("PE 签名不对")

    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    # PE32+ 的 DataDirectory 偏移是 112，PE32 是 96
    dd = opt + (112 if magic == 0x20B else 96)
    res_rva, _ = struct.unpack_from("<II", data, dd + 2 * 8)

    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        base = sec_off + i * 40
        name = data[base:base + 8].rstrip(b"\0").decode("latin1")
        vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, base + 8)
        sections.append((name, va, vsize, raw_off, raw_size))

    return {"data": data, "sections": sections, "res_rva": res_rva, "subsystem": subsystem}


def rva_to_off(sections, rva):
    for name, va, vsize, raw_off, raw_size in sections:
        if va <= rva < va + max(vsize, raw_size):
            return raw_off + (rva - va)
    return None


def resource_types(pe):
    """返回 {类型 ID: 该类型下的条目数}。"""
    data, sections, res_rva = pe["data"], pe["sections"], pe["res_rva"]
    if res_rva == 0:
        return None
    res_off = rva_to_off(sections, res_rva)
    if res_off is None:
        return None

    def entries(off):
        named, ids = struct.unpack_from("<HH", data, off + 12)
        out = []
        for i in range(named + ids):
            e = off + 16 + i * 8
            name_id, offset = struct.unpack_from("<II", data, e)
            out.append((name_id & 0x7FFFFFFF, offset))
        return out

    return entries(res_off), res_off


def child_count(pe, res_off, offset):
    """数某个资源类型下面挂了几个条目（比如 RT_ICON 下有几个尺寸）。"""
    if not (offset & 0x80000000):
        return 0
    data = pe["data"]
    off = res_off + (offset & 0x7FFFFFFF)
    named, ids = struct.unpack_from("<HH", data, off + 12)
    return named + ids


def read_manifest(pe):
    got = resource_types(pe)
    if got is None:
        return None, "PE 里没有资源目录（既没有清单也没有图标）"
    top, res_off = got
    data, sections, res_rva = pe["data"], pe["sections"], pe["res_rva"]

    def entries(off):
        named, ids = struct.unpack_from("<HH", data, off + 12)
        out = []
        for i in range(named + ids):
            e = off + 16 + i * 8
            name_id, offset = struct.unpack_from("<II", data, e)
            out.append((name_id & 0x7FFFFFFF, offset))
        return out

    for type_id, off in top:
        if type_id != RT_MANIFEST or not (off & 0x80000000):
            continue
        for _, off2 in entries(res_off + (off & 0x7FFFFFFF)):
            if not (off2 & 0x80000000):
                continue
            for _, off3 in entries(res_off + (off2 & 0x7FFFFFFF)):
                if off3 & 0x80000000:
                    continue
                de = rva_to_off(sections, res_rva + off3)
                if de is None:
                    continue
                d_rva, d_size = struct.unpack_from("<II", data, de)
                d_off = rva_to_off(sections, d_rva)
                if d_off is None:
                    continue
                blob = data[d_off:d_off + d_size]
                for enc in ("utf-8-sig", "utf-16-le"):
                    try:
                        text = blob.decode(enc)
                        if "<assembly" in text:
                            return text, None
                    except UnicodeDecodeError:
                        pass
                return blob.decode("utf-8", "replace"), None
    return None, "资源目录里没有 RT_MANIFEST 条目"


def main():
    argv = sys.argv[1:] or ["netlens.exe"]
    for path in argv:
        print("=" * 62)
        print(path)
        print("=" * 62)
        try:
            pe = parse(path)
        except FileNotFoundError:
            print("  文件不存在\n")
            continue
        except ValueError as e:
            print("  ✗ %s\n" % e)
            continue

        sub = pe["subsystem"]
        mark = "✓" if sub == 2 else ("!" if sub == 3 else "?")
        print("  %s PE 子系统 = %d  %s" % (mark, sub, SUBSYSTEMS.get(sub, "未知")))

        got = resource_types(pe)
        if got is None:
            print("  ✗ 没有资源目录")
            continue
        top, res_off = got
        # 根目录下只有"类型"这一层，尺寸数量要再往下钻一层去数
        icons = sum(child_count(pe, res_off, o) for t, o in top if t == RT_ICON)
        groups = sum(child_count(pe, res_off, o) for t, o in top if t == RT_GROUP_ICON)
        if groups:
            print("  ✓ 图标资源：%d 个图标组 / %d 个尺寸" % (groups, icons))
        else:
            print("  ✗ 没有图标资源（任务栏和标题栏会是空白图标）")

        text, err = read_manifest(pe)
        if err:
            print("  ✗ %s" % err)
        else:
            level = "?"
            if 'level="requireAdministrator"' in text:
                level = "requireAdministrator（双击弹 UAC，图标带盾牌角标）"
            elif 'level="highestAvailable"' in text:
                level = "highestAvailable"
            elif 'level="asInvoker"' in text:
                level = "asInvoker（不请求提权）"
            print("  ✓ 清单 %d 字符，requestedExecutionLevel = %s" % (len(text), level))
            for line in text.strip().splitlines():
                if "requestedExecutionLevel" in line:
                    print("      " + line.strip())
        print()


if __name__ == "__main__":
    main()
