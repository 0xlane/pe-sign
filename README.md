# pe-sign

![language](https://img.shields.io/github/languages/top/0xlane/pe-sign)
![Crates.io Version](https://img.shields.io/crates/v/pe-sign)
![License](https://img.shields.io/badge/license-MIT-green)
[![dependency status](https://deps.rs/repo/github/0xlane/pe-sign/status.svg)](https://deps.rs/repo/github/0xlane/pe-sign)
[![docs.rs](https://img.shields.io/docsrs/pe-sign)](https://docs.rs/pe-sign/latest/pesign)
![Crates.io Size](https://img.shields.io/crates/size/pe-sign)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/pe-sign)](https://crates.io/crates/pe-sign)

[README](README.md) | [中文文档](README_zh.md)

`pe-sign` is a cross-platform tool developed in Rust, designed for parsing and verifying digital signatures in PE files. It provides a simple command-line interface that supports extracting certificates, verifying digital signatures, calculating Authenticode digests, and printing certificate information. It can be used as a standalone command-line tool or integrated into your Rust project as a dependency.

This project is based on the pe-sign command-line tool from repository [windows_pe_signature_research](https://github.com/0xlane/windows_pe_signature_research), with the OpenSSL dependency removed.

## Features

- **Extract Certificates**: Extract certificates from PE files.
- **Verify Signatures**: Check the validity of a PE file's digital signature.
- **Calculate Authenticode Digest**: Compute the Authenticode digest of a PE file.
- **Print Certificate Information**: Display detailed information about certificates in PE files.
- **Print Signer Information**: Show detailed signer information from PE files.

## CLI Tool

### Installation

Download the binary for your platform from the [`Releases`](https://github.com/0xlane/pe-sign/releases) page. On Linux and macOS, you can place it in the `/bin` directory or add it to the `PATH` environment variable. On Windows, you can place it in `C:\Windows\System32` or add it to the `PATH` environment variable.

Alternatively, if you have `Cargo` installed, you can easily install it by running `cargo install pe-sign -F build-binary`.

### Usage

```powershell
pe-sign (0.1.8) - REinject
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

#### Extracting the Signature Certificate

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

You can also output the results using pipes and redirection in addition to the `-o` option. Example:

```powershell
pesign.exe extract test.exe --pem > pkcs7.cer
pesign.exe extract test.exe --pem | openssl pkcs7 -inform PEM --print_certs -noout -text
```

Note: When using pipes or redirection in PowerShell, must include the ``--pem`` flag. Otherwise, the output DER binary data will be interpreted as a string by PowerShell.

#### Printing Certificate Information

The command-line tool provides an OpenSSL-like `--print_certs` feature, which outputs a similar format to OpenSSL:

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

Example:

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
            Modulus:
                00:cc:2e:a1:52:49:09:cc:22:ef:34:43:dc:41:a6:98:a0:1f:0f:69:
                1a:33:b2:92:a5:73:26:4e:1d:b9:e2:ab:c4:46:e1:3e:f9:24:c2:f6:
                ...
                ...
            Exponent: 65537 (0x10001)
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
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertHighAssuranceCodeSigningCA-1.crt
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

Additionally, use the `--signer-info` option to print signer information. Example:

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

#### Verifying the Signature

The tool also verifies the validity of PE file signatures:

```powershell
Check the digital signature of a PE file for validity

Usage: pesign.exe verify [OPTIONS] <FILE>

Arguments:
  <FILE>

Options:
      --no-check-time   Ignore certificate validity time
      --ca-file <FILE>  Trusted certificates file
      --embed           Verify embedded certificate
  -h, --help            Print help
```

Use the `--no-check-time` option to skip the time validity check. And use the `--ca-file` option to specify a PEM-formatted trusted CA certificate file. If not specified, it will use the default built-in ca certificates for verification.

## Library Integration

You can also integrate `pe-sign` into your project as a dependency. Add it using the following command:

```rust
cargo add pe-sign
```

Then use `pesign` and parse PE file sigature to `PeSign` struct in `main.rs`:

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

For more details, please refer to the crate [documentation](https://docs.rs/pe-sign/latest/pesign).

## Contribution

If you find any issues or have suggestions for new features, feel free to submit an [Issue](https://github.com/0xlane/pe-sign/issues) or create a Pull Request.

## Repository

You can view the project's source code here: [pe-sign GitHub Repository](https://github.com/0xlane/pe-sign).

## License

This project is open-source under the MIT License. For more details, see the [LICENSE](https://github.com/0xlane/pe-sign/blob/main/LICENSE) file.
