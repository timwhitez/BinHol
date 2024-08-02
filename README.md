# BinHol
Binary Hollowing

2024-08-02更新 加入证书表处理 function模式动态适配函数大小

三种方式在你的pe二进制中插入恶意代码，如果有其他更好的方式欢迎补充

Usage: program [-sign] function/entrypoint/tlsinject <modify_pe_file_path> <shellcode_or_pe_path>

without using capstone/gapstone


- function patch

  ```
  binhol.exe function .\7za.exe .\calc.text
  binhol.exe -sign function .\7za.exe .\calc.text
  ```

- entrypoint hijack

  ```
  binhol.exe entrypoint .\7za.exe .\calc.text
  binhol.exe -sign entrypoint .\7za.exe .\calc.text
  ```

- tls injection

  ```
  binhol.exe tlsinject .\7za.exe .\calc.text
  binhol.exe -sign tlsinject .\7za.exe .\calc.text
  ```
