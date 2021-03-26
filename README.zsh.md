# Notarised Append Only Memory (NAOM)

NAOM repo包含设置Zenotta区块链的本地实例并与之交互所需的所有代码。
其他语言选项可以在这里找到:

- [English](https://gitlab.com/zenotta/naom/-/blob/main/README.md)
- [Deutsch](https://gitlab.com/zenotta/naom/-/blob/main/README.de.md)
- [Française](https://gitlab.com/zenotta/naom/-/blob/main/README.fr.md)
- [Afrikaans](https://gitlab.com/zenotta/naom/-/blob/main/README.af.md)

如果你想帮助翻译，或发现错误，请随时打开一个新的合并请求。

..

## 开发

NAOM的开发需要以下装置：

- [Rust](https://www.rust-lang.org/tools/install)

你可以克隆这个repo，并按以下方式运行测试。

```
cargo build
cargo test
```

在推送任何代码到这个repo之前，建议你从根目录下运行`make`来格式化和精简CI的代码。

..

## 使用

运行 `cargo run --bin main`将列出本地实例上的所有资产。一般来说，NAOM并不打算成为
直接使用，而是打算从其他需要访问区块链数据的程序中使用 
结构。