# BinHol
Binary Hollowing

三种方式在你的pe二进制中插入恶意代码

Usage: program function/entrypoint/tlsinject <modify_pe_file_path> <shellcode_or_pe_path>

without using capstone/gapstone


- function patch

  ```
  binhol.exe function .\7za.exe .\calc.text
  ```

- entrypoint hijack

  ```
  binhol.exe entrypoint .\7za.exe .\calc.text
  ```

- tls injection

  ```
  binhol.exe tlsinject .\7za.exe .\calc.text
  ```
