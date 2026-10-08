"""生成 app.ico（netlens 的程序图标），不依赖任何第三方库。

图形：深色圆角方块 + 金色菱形 + 一道横向缝隙（"透镜"的意象）。
用 4 倍超采样做抗锯齿，小尺寸下才不至于糊成一团。

尺寸 <=64 用传统 BMP(DIB) 存储，256 用 PNG —— 这是 Windows 图标的惯例：
虽然 Vista 之后 PNG 各尺寸都能读，但老组件（某些 shell 扩展、老版资源管理器）
只认 DIB，混着来最稳。

用法：python makeicon.py [输出路径，默认 app.ico]
"""
import struct
import sys
import zlib

SIZES = [16, 24, 32, 48, 64, 128, 256]
SS = 4  # 超采样倍数

BG = (18, 21, 29)
BORDER = (52, 61, 78)
GOLD = (232, 176, 75)

# 所有几何都在 256x256 的坐标系里描述
CANVAS = 256.0
INSET = 6.0
RADIUS = 52.0
BORDER_W = 6.0
DIAMOND_R = 66.0   # 菱形半径（|dx|+|dy| <= R）
SLIT_HALF_X = 40.0
SLIT_HALF_Y = 9.0


def rounded(px, py, lo, hi, r):
    """点是否落在 [lo,hi] 区间、圆角半径 r 的圆角矩形内。"""
    if px < lo or px > hi or py < lo or py > hi:
        return False
    cx = min(max(px, lo + r), hi - r)
    cy = min(max(py, lo + r), hi - r)
    dx, dy = px - cx, py - cy
    return dx * dx + dy * dy <= r * r


def sample(px, py):
    """返回该点的 RGBA。px/py 在 256 坐标系里。"""
    if not rounded(px, py, INSET, CANVAS - INSET, RADIUS):
        return (0, 0, 0, 0)

    color = BG
    if not rounded(px, py, INSET + BORDER_W, CANVAS - INSET - BORDER_W, RADIUS - BORDER_W):
        color = BORDER

    dx = abs(px - CANVAS / 2)
    dy = abs(py - CANVAS / 2)
    if dx + dy <= DIAMOND_R:
        # 中间那道横向缝隙：金色菱形被切出一条暗缝，
        # 但左右两个尖角还连着，整体仍然读得出是菱形
        if not (dx <= SLIT_HALF_X and dy <= SLIT_HALF_Y):
            color = GOLD
    return (color[0], color[1], color[2], 255)


def render(size):
    """渲染 size x size 的 RGBA 像素，返回逐行的 bytes。"""
    scale = CANVAS / size
    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    px = (x + (sx + 0.5) / SS) * scale
                    py = (y + (sy + 0.5) / SS) * scale
                    cr, cg, cb, ca = sample(px, py)
                    r += cr * ca
                    g += cg * ca
                    b += cb * ca
                    a += ca
            n = SS * SS
            if a == 0:
                row += bytes((0, 0, 0, 0))
            else:
                row += bytes((r // a, g // a, b // a, a // n))
        rows.append(bytes(row))
    return rows


def png_bytes(rows, size):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) +
            chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def dib_bytes(rows, size):
    """ICO 里的传统格式：BITMAPINFOHEADER + 自下而上的 BGRA + AND 掩码。"""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    body = b"".join(
        b"".join(bytes((px[2], px[1], px[0], px[3])) for px in
                 [rows[y][i * 4:i * 4 + 4] for i in range(size)])
        for y in range(size - 1, -1, -1)
    )
    mask_row = ((size + 31) // 32) * 4  # 每行按 4 字节对齐
    return header + body + b"\x00" * (mask_row * size)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "app.ico"
    entries = []
    for size in SIZES:
        rows = render(size)
        data = png_bytes(rows, size) if size >= 256 else dib_bytes(rows, size)
        entries.append((size, data))
        print("  %3dx%-3d %6d 字节  %s" % (size, size, len(data), "PNG" if size >= 256 else "DIB"))

    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = len(header) + 16 * len(entries)
    dirs, blobs = b"", b""
    for size, data in entries:
        w = 0 if size >= 256 else size
        h = 0 if size >= 256 else size
        dirs += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)

    with open(out, "wb") as f:
        f.write(header + dirs + blobs)
    print("%s  %d 字节  %d 个尺寸" % (out, len(header) + len(dirs) + len(blobs), len(entries)))


if __name__ == "__main__":
    main()
