# pe-sign

![language](https://img.shields.io/github/languages/top/0xlane/pe-sign)
![Crates.io Version](https://img.shields.io/crates/v/pe-sign)
![License](https://img.shields.io/badge/license-MIT-green)
[![dependency status](https://deps.rs/repo/github/0xlane/pe-sign/status.svg)](https://deps.rs/repo/github/0xlane/pe-sign)
[![docs.rs](https://img.shields.io/docsrs/pe-sign)](https://docs.rs/pe-sign/latest/pesign)
![Crates.io Size](https://img.shields.io/crates/size/pe-sign)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/pe-sign)](https://crates.io/crates/pe-sign)

[README](README.md) | [中文文档](README_zh.md)

`pe-sign` 是一个用 Rust 语言开发的跨平台工具，专为解析和验证 PE 文件中的数字签名而设计。它既可以作为独立的命令行工具使用，也可以作为依赖库集成到任何 Rust 项目中。支持提取证书、验证签名、计算 Authenticode 签名摘要以及打印证书详细信息。

该项目基于对仓库 [windows_pe_signature_research](https://github.com/0xlane/windows_pe_signature_research) 中的 pe-sign 命令行工具改造所得，去除了 openssl 依赖。

## 功能

- **提取证书**: 从 PE 文件中提取证书。
- **验证签名**: 检查 PE 文件的数字签名是否有效。
- **计算 Authenticode 摘要**: 计算 PE 文件的 Authenticode 摘要。
- **打印证书信息**: 显示 PE 文件中证书的详细信息。
- **打印签名者信息**: 显示 PE 文件签名都的详细信息。

## 命令行工具

### 安装

直接下载 Release 中对应平台的二进制文件使用，Linux、Mac 系统可直接放入 /bin 目录下或 PATH 全局变量中，Windows 可放入 C:\Windows\System32 目录下或 PATH 全局变量中。

### 使用说明

```powershell
pe-sign (0.1.2) - REinject
A tool for parsing and verifing PE file signatures

Repository: https://github.com/0xlane/pe-sign

Commands:
  extract  Extract the certificate of a PE file
  verify   Check the digital signature of a PE file for validity
  calc     Calculate the authticode digest of a PE file
  print    Print the certificate information of a PE file.
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### 提取签名证书

```powershell
Extract the certificate of a PE file

Usage: pesign.exe extract [OPTIONS] <FILE>

Arguments:
  <FILE>

Options:
  -o, --output <FILE>  Write to file instead of stdout
      --pem            Extract and convert certificate to pem format
      --embed          Extract embedded certificate
  -h, --help           Print help
```

除了使用 `-o` 选项，还支持管道、重定向方式输出，示例：

```powershell
pesign.exe extract test.exe --pem > pkcs7.cer
pesign.exe extract test.exe --pem | openssl pkcs7 -inform PEM --print_certs -noout -text
```

需要注意的是，在 powrershell 中使用管道、重定向时请添加 `--pem` 参数，否则输出的 DER 二进制数据会被 powershell 看作字符串转义。

#### 打印证书信息

命令行工具提供了类似 openssl 的 `--print_certs` 功能，与 openssl 输出格式基本一致：

```powershell
Print the certificate information of a PE file.

Usage: pesign.exe print [OPTIONS] <FILE>

Arguments:
  <FILE>

Options:
      --signer-info  Print the signer info of a PE file.
  -a, --all          Include nested signature.
  -h, --help         Print help
```

示例：

```powershell
PS C:\dev\pe-sign> pesign.exe print .\ProcessHacker.exe
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0f:f1:ef:66:bd:62:1c:65:b7:4b:4d:e4:14:25:71:7f
        Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance Code Signing CA-1
        Not Before: 2013-10-30 08:00:00 +08:00
        Not After : 2017-01-04 20:00:00 +08:00
        Subject: C=AU, ST=New South Wales, L=Sydney, O=Wen Jia Liu, CN=Wen Jia Liu
        Subject Public Key Info:
            Algorithm: RSA
            Public-Key: (2048 bit)
            Modules:
                00:cc:2e:a1:52:49:09:cc:22:ef:34:43:dc:41:a6:98:a0:1f:0f:69:
                1a:33:b2:92:a5:73:26:4e:1d:b9:e2:ab:c4:46:e1:3e:f9:24:c2:f6:
                ...
                ...
        Extensions:
            Authority Key Identifier:
                97:48:03:eb:15:08:6b:b9:b2:58:23:cc:94:2e:f1:c6:65:d2:64:8e
            Subject Key Identifier:
                2c:b8:9a:96:b2:c1:b1:a0:7d:a4:90:20:19:b8:be:05:58:df:2c:78
            Key Usage:
                Digital Signature
            Extended Key Usage:
                Code Signing
            CRL Distribution Points:
                Full Name:
                    URI:http://crl3.digicert.com/ha-cs-2011a.crl
                Full Name:
                    URI:http://crl4.digicert.com/ha-cs-2011a.crl
            Certificate Policies: <Unsupported>
            Authority Information Access:
                1.3.6.1.5.5.7.48.1 - URI:http://ocsp.digicert.com
                1.3.6.1.5.5.7.48.2 - URI:http://cacerts.digicert.com/DigiCertHighAssuranceCodeSigningCA-1.crt
            Basic Constraints:
                ca:FALSE
    Signature Algorithm: Sha1WithRSA
    Signature Value:
            88:f1:59:8a:6a:8a:6c:49:04:64:67:70:02:14:76:57:3d:57:c2:f9:
            cb:88:78:6e:82:3a:63:12:f7:c9:0b:57:8b:13:16:b0:69:d7:67:0f:
            ...
            ...

...
...
```

另外，还可以使用 `--signer-info` 选项打印签名者信息，示例：

```powershell
PS C:\dev\pe-sign> pesign.exe print .\ProcessHacker.exe --signer-info
Signer Info:
    Signer Identifier:
        Issuer And Serial Number:
            Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance Code Signing CA-1
            Serial Number:
                0f:f1:ef:66:bd:62:1c:65:b7:4b:4d:e4:14:25:71:7f
    Authenticated Attributes:
        1.3.6.1.4.1.311.2.1.12:
            30:00
        1.2.840.113549.1.9.3:
            06:0a:2b:06:01:04:01:82:37:02:01:04
        1.3.6.1.4.1.311.2.1.11:
            30:0c:06:0a:2b:06:01:04:01:82:37:02:01:15
        1.2.840.113549.1.9.4:
            04:14:f4:23:ed:d4:63:5b:6b:ea:f3:c8:ca:9c:de:5d:db:5f:8b:1a:
            ba:20
    Unauthenticated Attributes:
        Counter Signature (1.2.840.113549.1.9.6):
            30:82:01:f8:02:01:01:30:76:30:62:31:0b:30:09:06:03:55:04:06:
            13:02:55:53:31:15:30:13:06:03:55:04:0a:13:0c:44:69:67:69:43:
            ...
            ...
        1.3.6.1.4.1.311.2.4.1:
            30:82:1c:23:06:09:2a:86:48:86:f7:0d:01:07:02:a0:82:1c:14:30:
            82:1c:10:02:01:01:31:0f:30:0d:06:09:60:86:48:01:65:03:04:02:
            ...
            ...
    Countersigner Info:
        Signer Info:
            Signer Identifier:
                Issuer And Serial Number:
                    Issuer: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Assured ID CA-1
                    Serial Number:
                        03:01:9a:02:3a:ff:58:b1:6b:d6:d5:ea:e6:17:f0:66
            Authenticated Attributes:
                1.2.840.113549.1.9.3:
                    06:09:2a:86:48:86:f7:0d:01:07:01
                Signing Time (1.2.840.113549.1.9.5):
                    2016-03-29 09:35:02 +08:00
                1.2.840.113549.1.9.4:
                    04:14:d4:11:7e:ce:3a:3f:29:91:7d:e3:f0:55:fe:32:a2:11:b0:c9:
                    c5:ac
            Digest Algorithm: Sha1
            Encrypted Digest:
                02:d1:d6:d2:ec:f6:cb:7a:4b:a4:29:01:ab:77:48:e9:d5:bf:0f:6c:
                bd:b7:d6:86:11:24:e8:cf:ba:32:ab:12:40:be:31:e7:d6:16:c5:52:
                ...
                ...
    Digest Algorithm: Sha1
    Encrypted Digest:
        46:3d:97:37:67:9d:12:4e:80:cf:a1:df:98:10:8d:a8:39:3e:5e:db:
        28:c3:28:c9:d7:a7:48:22:2d:a8:4c:1e:40:e9:72:63:fd:04:7a:e9:
        ...
        ...
```

### 验证签名

命令行工具也可用于验证签名有效性：

```powershell
Check the digital signature of a PE file for validity

Usage: pesign.exe verify [OPTIONS] <FILE>

Arguments:
  <FILE>

Options:
      --no-check-time   Ignore certificate validity time
      --ca-file <FILE>  Trusted certificates file
  -h, --help            Print help
```

使用 `--no-check-time` 选项可跳过签名时间有效性检查，`--ca-file` 选项用于指定 PEM 格式的可信 CA 证书，若不指定则使用内置的默认证书进行有效性验证。

## 作为项目依赖库

你也可以将 `pe-sign` 添加为依赖，集成到自己的项目中。使用以下命令添加依赖：

```rust
cargo add pe-sign
```

然后在 `main.rs` 导入 `pesign` 并且解析为 `PeSign` 结构：

```rust
use pesign::PeSign;

fn main() {
    if let Some(pesign) = PeSign::from_pe_path("test.exe").unwrap() {
        // Add your program logic.
    } else {
        println!("The file is no signed!!");
    }
}
```

更多详细信息，请参阅 crate [文档](https://docs.rs/pe-sign/latest/pesign)。

## 贡献

如果你发现问题或者有新的功能建议，欢迎提交 [Issue](https://github.com/0xlane/pe-sign/issues) 或发起 Pull Request。

## 仓库

你可以在此处查看项目的源码：[pe-sign GitHub 仓库](https://github.com/0xlane/pe-sign)

## 许可证

该项目基于 MIT 许可证开源。详情请查看 [LICENSE](https://github.com/0xlane/pe-sign/blob/main/LICENSE) 文件。
