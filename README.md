# BinHol
Binary Hollowing
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
