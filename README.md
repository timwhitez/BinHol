# BinHol
Binary Hollowing

2024-09-02更新 1. 修复bug 2. function模式支持golang exe对于初始化阶段的patch 3.支持对于dll导出函数的patch

2024-08-02更新 1. 加入证书表处理 2. function模式动态适配函数大小

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


# 说明
function方法抄的大佬的python项目https://github.com/yj94/BinarySpy, 感谢大佬开源，忘记写来源了抱歉

tls方法抄的大佬的 https://github.com/aaaddress1/sakeInject 项目

entrypoint 方法来源我之前写的进程注入项目
