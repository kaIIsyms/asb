AMSI bypass by memory patching AmsiScanBuffer

- Highly inspired by [AmsiScanBufferBypass](https://github.com/rasta-mouse/AmsiScanBufferBypass)
- ASB patching in runtime
  - Indirect syscalls execution
    - Syscall stomping technique
    - (today there is some EDRs that can detect it)
  - Dynamic WinAPI resolution

(C) gbr 2025
