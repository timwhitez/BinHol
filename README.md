# BinHol (Binary Hollowing)

BinHol 是一个强大的二进制文件修改工具，专门用于在 Windows PE（可执行）文件中插入自定义代码。这个项目提供了三种不同的代码注入技术，使用 Go 语言实现，为安全研究和软件测试提供了灵活的解决方案。

> 注：本README由AI生成，内容可能需要进一步人工审核和修改。

## 更新日志

### 2024-09-02更新
1. 修复bug
2. function模式支持golang exe对于初始化阶段的patch
3. 支持对于dll导出函数的patch

### 2024-08-02更新
1. 加入证书表处理
2. function模式动态适配函数大小

## 功能特点

- 支持三种不同的代码注入方法：
  1. 函数补丁（Function Patch）
  2. 入口点劫持（Entrypoint Hijack）
  3. TLS 注入（TLS Injection）
- 可选的数字签名处理
- 动态适应函数大小（在函数模式下）
- 证书表处理
- 命令行界面，易于使用
- 无需依赖 Capstone/Gapstone 库

## 安装

1. 确保你的系统上安装了 Go 编程语言（推荐 Go 1.15 或更高版本）。
2. 克隆仓库：
   ```
   git clone https://github.com/timwhitez/BinHol.git
   ```
3. 进入项目目录：
   ```
   cd BinHol
   ```
4. 编译项目：
   ```
   go build -o binhol.exe main.go
   ```

## 使用方法

基本用法：
```
binhol.exe [-sign] <injection_method> <target_pe_file> <shellcode_or_pe_file>
```

参数说明：
- `-sign`：可选参数，用于处理数字签名
- `<injection_method>`：注入方法，可选 `function`、`entrypoint` 或 `tlsinject`
- `<target_pe_file>`：目标 PE 文件路径
- `<shellcode_or_pe_file>`：包含 shellcode 或要注入的 PE 文件路径

示例：

1. 函数补丁方法：
   ```
   binhol.exe function .\7za.exe .\calc.text
   binhol.exe -sign function .\7za.exe .\calc.text
   ```

2. 入口点劫持方法：
   ```
   binhol.exe entrypoint .\7za.exe .\calc.text
   binhol.exe -sign entrypoint .\7za.exe .\calc.text
   ```

3. TLS 注入方法：
   ```
   binhol.exe tlsinject .\7za.exe .\calc.text
   binhol.exe -sign tlsinject .\7za.exe .\calc.text
   ```

## 实现原理

1. 函数补丁：修改目标 PE 文件中的特定函数，插入自定义代码。
2. 入口点劫持：修改 PE 文件的入口点，使其首先执行注入的代码。
3. TLS 注入：利用 Windows 的线程本地存储（TLS）机制注入代码。

每种方法都有其特点和适用场景，可以根据需要选择合适的注入技术。

## 注意事项

- 本工具仅用于教育和研究目的。在实际使用中，请确保遵守相关法律法规。
- 修改二进制文件可能会导致目标程序不稳定或无法运行，请谨慎使用。
- 建议在使用前备份目标 PE 文件。
- 某些防病毒软件可能会将修改后的文件标记为潜在威胁。

## 致谢

- 函数补丁方法参考了 [BinarySpy](https://github.com/yj94/BinarySpy) 项目
- TLS 注入方法参考了 [sakeInject](https://github.com/aaaddress1/sakeInject) 项目
- 入口点劫持方法基于作者之前的进程注入项目

特别感谢以上项目的作者们的开源贡献。
