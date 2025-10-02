# Memory-Scanner
A Windows user-mode memory scanner that searches for byte signatures with wildcards (??) and ASCII/UTF-16LE strings (with regex filtering), supports a live mode showing only new hits, and can save results in JSON. It uses WinAPI (ReadProcessMemory, VirtualQueryEx) with minimal privileges for safe process scanning.
