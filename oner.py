#!/usr/bin/env python3
"""
memscan — быстрый user‑mode сканер памяти для Windows.
Ищет сигнатуры по байтам (с wildcard'ами) и строки (ASCII/UTF‑16), умеет live‑режим и JSON‑отчёт.
"""
from __future__ import annotations
import argparse
import base64
import ctypes as C
from ctypes import wintypes as W
import datetime as dt
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil  # type: ignore
except Exception:
    print("[FATAL] pip install psutil", file=sys.stderr); raise

if os.name != 'nt':
    print('[FATAL] Windows only'); sys.exit(1)

kernel32 = C.WinDLL('kernel32', use_last_error=True)
psapi    = C.WinDLL('psapi', use_last_error=True)

PROCESS_QUERY_INFORMATION      = 0x0400
PROCESS_VM_READ                = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100
READABLE_MASK = {
    0x02,   # PAGE_READONLY
    0x04,   # PAGE_READWRITE
    0x08,   # PAGE_WRITECOPY
    0x20,   # PAGE_EXECUTE_READ
    0x40,   # PAGE_EXECUTE_READWRITE
    0x80,   # PAGE_EXECUTE_WRITECOPY
}

class MEMORY_BASIC_INFORMATION(C.Structure):
    _fields_ = [
        ('BaseAddress',      C.c_void_p),
        ('AllocationBase',   C.c_void_p),
        ('AllocationProtect',W.DWORD),
        ('RegionSize',       C.c_size_t),
        ('State',            W.DWORD),
        ('Protect',          W.DWORD),
        ('Type',             W.DWORD),
    ]

VirtualQueryEx     = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MEMORY_BASIC_INFORMATION), C.c_size_t]
VirtualQueryEx.restype  = C.c_size_t

OpenProcess        = kernel32.OpenProcess
OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
OpenProcess.restype  = W.HANDLE

ReadProcessMemory  = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
ReadProcessMemory.restype  = W.BOOL

CloseHandle        = kernel32.CloseHandle
CloseHandle.argtypes = [W.HANDLE]
CloseHandle.restype  = W.BOOL

# Важно: wildcard‑сигнатуры вида "48 8B ?? 05 ?? E8" -> байтовый regex
def compile_sig(name: str, pattern: str) -> Tuple[str, re.Pattern[bytes], str]:
    toks = [t for t in pattern.strip().split() if t]
    bs = []
    for t in toks:
        if t == '??' or t == 'wild' or t == '**':
            bs.append(b'.')
        else:
            if len(t) != 2 or any(c not in '0123456789abcdefABCDEF' for c in t):
                raise ValueError(f'bad token in pattern: {t}')
            bs.append(b'\x' + t.encode())
    regex = b''.join(bs)
    return name, re.compile(regex, re.DOTALL), pattern

def compile_sigs(sig_args: List[str], sig_file: Optional[str]) -> List[Tuple[str, re.Pattern[bytes], str]]:
    out = []
    auto_id = 1
    if sig_file:
        with open(sig_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if '=' in line:
                    nm, pat = line.split('=', 1)
                else:
                    nm, pat = f'sig_{auto_id}', line
                    auto_id += 1
                out.append(compile_sig(nm.strip(), pat.strip()))
    for s in sig_args:
        if '=' in s: nm, pat = s.split('=', 1)
        else: nm, pat = f'sig_{auto_id}', s; auto_id += 1
        out.append(compile_sig(nm.strip(), pat.strip()))
    return out

# Поиск строк — просто и быстро, без красоты
def extract_strings(buf: bytes, min_len: int, utf16: bool) -> List[Tuple[int, str]]:
    res: List[Tuple[int, str]] = []
    # ASCII
    cur: List[int] = []
    start = 0
    for i, b in enumerate(buf):
        if 32 <= b <= 126:
            if not cur: start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                res.append((start, bytes(cur).decode('ascii', 'ignore')))
            cur = []
    if len(cur) >= min_len:
        res.append((start, bytes(cur).decode('ascii', 'ignore')))
    if not utf16: return res
    # UTF‑16LE
    cur = []
    start = None
    i = 0
    while i + 1 < len(buf):
        c0, c1 = buf[i], buf[i+1]
        if c1 == 0 and 32 <= c0 <= 126:
            if start is None: start = i
            cur.append(c0)
            i += 2
        else:
            if start is not None and len(cur) >= min_len:
                res.append((start, bytes(cur).decode('ascii', 'ignore')))
            cur = []
            start = None
            i += 2
    if start is not None and len(cur) >= min_len:
        res.append((start, bytes(cur).decode('ascii', 'ignore')))
    return res

def open_process(pid: int) -> W.HANDLE:
    # Ключевое: минимум прав, чтобы читать память
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise OSError(f'OpenProcess failed for PID {pid} (need rights)')
    return h

def regions(h: W.HANDLE) -> List[Tuple[int, int, int, int]]:
    out = []
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    maxaddr = (1 << (C.sizeof(C.c_void_p) * 8)) - 1
    while addr < maxaddr:
        ret = VirtualQueryEx(h, C.c_void_p(addr), C.byref(mbi), C.sizeof(mbi))
        if not ret: break
        base = C.cast(mbi.BaseAddress, C.c_size_t).value or 0
        size = int(mbi.RegionSize)
        prot = int(mbi.Protect)
        state = int(mbi.State)
        out.append((base, size, prot, state))
        addr = base + size
    # фильтруем только читаемые коммитнутые регионы без guard
    filt = []
    for base, size, prot, state in out:
        if state != MEM_COMMIT: continue
        if prot & PAGE_GUARD or prot & PAGE_NOACCESS: continue
        if READABLE_MASK and (prot & 0xFF) not in READABLE_MASK: continue
        if size <= 0: continue
        filt.append((base, size, prot, state))
    return filt

def rpm(h: W.HANDLE, addr: int, size: int) -> bytes:
    buf = (C.c_ubyte * size)()
    read = C.c_size_t(0)
    if not ReadProcessMemory(h, C.c_void_p(addr), buf, size, C.byref(read)):
        return b''
    return bytes(buf[:read.value])

def scan_once(pid: int, sigs, str_regex: List[re.Pattern], min_len: int, utf16: bool, chunk: int = 1024*1024, overlap: int = 32) -> Dict[str, Any]:
    h = open_process(pid)
    try:
        proc = psutil.Process(pid)
    except Exception:
        proc = None
    meta = {
        'pid': pid,
        'name': (proc.name() if proc else None),
        'create_time': (dt.datetime.fromtimestamp(proc.create_time()).isoformat() if proc and proc.create_time() else None),
        'ts': dt.datetime.utcnow().isoformat() + 'Z',
    }
    hits: Dict[str, List[Dict[str, Any]]] = {'patterns': [], 'strings': []}
    for base, size, prot, state in regions(h):
        off = 0
        prev = b''
        while off < size:
            to_read = min(chunk, size - off)
            data = rpm(h, base + off, to_read)
            if not data:
                off += to_read
                prev = b''
                continue
            blob = prev + data
            # сигнатуры
            for nm, rgx, raw in sigs:
                for m in rgx.finditer(blob):
                    addr = base + off - len(prev) + m.start()
                    sample = blob[m.start():m.start()+16]
                    hits['patterns'].append({'name': nm, 'pattern': raw, 'addr': hex(addr), 'preview_hex': sample.hex()})
            # строки
            if str_regex:
                for pos, s in extract_strings(blob, min_len, utf16):
                    if any(r.search(s) for r in str_regex):
                        addr = base + off - len(prev) + pos
                        hits['strings'].append({'addr': hex(addr), 'text': s})
            prev = blob[-overlap:]
            off += to_read
    CloseHandle(h)
    return {'meta': meta, 'hits': hits}

def pid_from_args(pid: Optional[int], name: Optional[str]) -> int:
    if pid: return int(pid)
    if not name: raise SystemExit('specify --pid or --name')
    name_l = name.lower()
    cands = [p for p in psutil.process_iter(['pid','name']) if p.info.get('name','').lower() == name_l or name_l in p.info.get('name','').lower()]
    if not cands: raise SystemExit(f'process "{name}" not found')
    return cands[0].pid

def parse_regex_list(regexes: List[str]) -> List[re.Pattern]:
    out = []
    for r in regexes:
        try: out.append(re.compile(r))
        except Exception as e: raise SystemExit(f'bad regex "{r}": {e}')
    return out

def save_json(path: str, obj: Any) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def live_loop(pid: int, sigs, regexes, min_len: int, utf16: bool, interval: float, json_out: Optional[str], diff_only: bool) -> None:
    seen: set = set()
    try:
        while True:
            res = scan_once(pid, sigs, regexes, min_len, utf16)
            new = []
            for h in res['hits']['patterns']:
                key = ('p', h['name'], h['addr'])
                if key not in seen: seen.add(key); new.append(h)
            for h in res['hits']['strings']:
                key = ('s', h['text'], h['addr'])
                if key not in seen: seen.add(key); new.append(h)
            if diff_only:
                print(f"[{res['meta']['ts']}] new hits: {len(new)}")
                for h in new[:50]:
                    if 'name' in h:
                        print(f"  [pat] {h['name']} @ {h['addr']} preview={h.get('preview_hex')}")
                    else:
                        print(f"  [str] '{h['text']}' @ {h['addr']}")
            else:
                print(f"[{res['meta']['ts']}] total patterns={len(res['hits']['patterns'])} strings={len(res['hits']['strings'])}")
            if json_out:
                save_json(json_out, res)
            time.sleep(interval)
    except KeyboardInterrupt:
        print('\n[!] live stopped')

def build_cli():
    ap = argparse.ArgumentParser(description='memscan — user-mode memory scanner (Windows)')
    tgt = ap.add_argument_group('target')
    tgt.add_argument('--pid', type=int, help='PID процесса')
    tgt.add_argument('--name', help='имя процесса (substring ок)')
    sig = ap.add_argument_group('signatures')
    sig.add_argument('--sig', action='append', default=[], help='сигнатура: name=PATTERN или просто PATTERN; байты через пробел, ?? — wildcard')
    sig.add_argument('--sig-file', help='файл со списком сигнатур (по одной на строку)')
    st = ap.add_argument_group('strings')
    st.add_argument('--find', action='append', default=[], help='regex для фильтрации строк (можно несколько)')
    st.add_argument('--min-len', type=int, default=4, help='минимальная длина строки (ASCII/UTF-16)')
    st.add_argument('--no-utf16', action='store_true', help='не искать UTF-16LE строки')
    out = ap.add_argument_group('output')
    out.add_argument('--json-out', help='сохранить JSON-отчёт сюда')
    out.add_argument('--live', type=float, help='интервал live-сканирования в секундах')
    out.add_argument('--diff-only', action='store_true', help='в live выводить только новые находки')
    return ap

def main(argv: Optional[List[str]] = None) -> int:
    ap = build_cli(); args = ap.parse_args(argv)
    pid = pid_from_args(args.pid, args.name)
    sigs = compile_sigs(args.sig, args.sig_file)
    regexes = parse_regex_list(args.find)
    utf16 = not args.no_utf16

    if args.live:
        live_loop(pid, sigs, regexes, args.min_len, utf16, args.live, args.json_out, args.diff_only)
        return 0

    res = scan_once(pid, sigs, regexes, args.min_len, utf16)
    print(f"[{res['meta']['ts']}] scanned pid={pid} name={res['meta']['name']} patterns={len(res['hits']['patterns'])} strings={len(res['hits']['strings'])}")
    for h in res['hits']['patterns'][:50]:
        print(f"  [pat] {h['name']} @ {h['addr']} preview={h.get('preview_hex')}")
    for h in res['hits']['strings'][:50]:
        print(f"  [str] '{h['text']}' @ {h['addr']}")
    if args.json_out: save_json(args.json_out, res); print(f"[+] JSON saved: {args.json_out}")
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
