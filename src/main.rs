use std::{
    default::Default,
    error::Error,
    fs::File,
    io::{BufWriter, IsTerminal, Write},
    path::PathBuf,
};

use pesign::{PeSign, VerifyOption};
use pretty_hex::pretty_hex_write;

fn cli() -> clap::Command {
    use clap::{arg, value_parser, Command};

    Command::new("pe-sign")
        .version("0.1.5")
        .about("A tool for parsing and verifing PE file signatures\n\nRepository: https://github.com/0xlane/pe-sign\n")
        .author("REinject")
        .help_template("{name} ({version}) - {author}\n{about}\n{all-args}")
        .subcommand_required(true)
        .subcommand(
            Command::new("extract")
                .about("Extract the certificate of a PE file")
                .args(&[
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                    arg!(-o --output <FILE> "Write to file instead of stdout")
                        .value_parser(value_parser!(PathBuf)),
                    arg!(--pem "Extract and convert certificate to pem format"),
                    arg!(--embed "Extract embedded certificate"),
                ]),
        )
        .subcommand(
            Command::new("verify")
                .about("Check the digital signature of a PE file for validity")
                .args(&[
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                    arg!(--"no-check-time" "Ignore certificate validity time"),
                    arg!(--"ca-file" <FILE> "Trusted certificates file")
                        .value_parser(value_parser!(PathBuf)),
                ]),
        )
        .subcommand(
            Command::new("calc")
                .about("Calculate the authticode digest of a PE file")
                .args(&[
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                    arg!(-a --algorithm <ALGORITHM> "Hash algorithm")
                        .value_parser(["sha1", "sha224", "sha256", "sha384", "sha512"])
                        .default_value("sha256"),
                ]),
        )
        .subcommand(
            Command::new("print")
                .about("Print the certificate information of a PE file")
                .args(&[
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                    arg!(--"signer-info" "Print the signer info of a PE file"),
                    arg!(-a --all "Include nested signature"),
                ]),
        )
}

fn main() -> Result<(), Box<dyn Error>> {
    // 解析参数
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("extract", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let pem = sub_matches.get_flag("pem");
            let embedded = sub_matches.get_flag("embed");

            // 从文件解析 pkcs7 签名数据
            let pesign = match PeSign::from_pe_path(file)? {
                Some(pesign) => match embedded {
                    true => match pesign.signed_data.signer_info.get_nested_signature()? {
                        Some(nested_pesign) => nested_pesign,
                        None => {
                            println!("The file is no nested signature!!");
                            return Ok(());
                        }
                    },
                    false => pesign,
                },
                None => {
                    println!("The file is no signed!!");
                    return Ok(());
                }
            };

            // 输出到文件
            let export_bytes = match pem {
                true => pesign.export_pem()?.as_bytes().to_vec(),
                false => pesign.export_der()?,
            };

            let is_terminal = std::io::stdout().is_terminal();
            let output = sub_matches.get_one::<PathBuf>("output");
            let mut out_writer = BufWriter::new(match output {
                Some(output) => Box::new(File::create(output)?) as Box<dyn Write>,
                None => Box::new(std::io::stdout()) as Box<dyn Write>,
            });

            if output.is_none() && !pem && is_terminal {
                let mut str = String::new();
                pretty_hex_write(&mut str, &export_bytes)?;
                out_writer.write_all(str.as_bytes())?;
            } else {
                out_writer.write_all(&export_bytes)?;
            }

            Ok(())
        }
        Some(("verify", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let check_time = !sub_matches.get_flag("no-check-time");
            let trusted_ca_pem_file = sub_matches.get_one::<PathBuf>("ca-file");

            let trusted_ca_pem = match trusted_ca_pem_file {
                Some(trusted_ca_pem_file) => Some(std::fs::read_to_string(trusted_ca_pem_file)?),
                None => None,
            };

            match PeSign::from_pe_path(file)? {
                Some(pesign) => {
                    println!(
                        "{:?}",
                        pesign.verify_pe_path(
                            file,
                            &VerifyOption {
                                check_time,
                                trusted_ca_pem
                            }
                        )?
                    );
                }
                None => {
                    println!("The file is no signed!!");
                }
            }

            Ok(())
        }
        Some(("calc", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let algorithm_str = sub_matches.get_one::<String>("algorithm").unwrap();

            let algorithm = match algorithm_str.as_str() {
                "sha1" => pesign::cert::Algorithm::Sha1,
                "sha224" => pesign::cert::Algorithm::Sha224,
                "sha256" => pesign::cert::Algorithm::Sha256,
                "sha384" => pesign::cert::Algorithm::Sha384,
                "sha512" => pesign::cert::Algorithm::Sha512,
                _ => unreachable!(),
            };

            println!(
                "{}",
                PeSign::calc_authenticode_from_pe_path(&file, &algorithm)?
            );

            Ok(())
        }
        Some(("print", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let all = sub_matches.get_flag("all");
            let print_signer = sub_matches.get_flag("signer-info");

            match PeSign::from_pe_path(file)? {
                Some(pesign) => {
                    if print_signer {
                        println!("{}", pesign.signed_data.signer_info);

                        if all {
                            match pesign.signed_data.signer_info.get_nested_signature()? {
                                Some(nested) => {
                                    println!("============");
                                    println!("{}", nested.signed_data.signer_info);
                                }
                                None => {}
                            }
                        }
                    } else {
                        println!(
                            "{}",
                            pesign
                                .signed_data
                                .cert_list
                                .iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<String>>()
                                .join("\n\n")
                        );

                        if all {
                            match pesign.signed_data.signer_info.get_nested_signature()? {
                                Some(nested) => {
                                    println!("============");
                                    println!(
                                        "{}",
                                        nested
                                            .signed_data
                                            .cert_list
                                            .iter()
                                            .map(|v| v.to_string())
                                            .collect::<Vec<String>>()
                                            .join("\n\n")
                                    );
                                }
                                None => {}
                            }
                        }
                    }
                }
                None => {
                    println!("The file is no signed!!");
                }
            }

            Ok(())
        }
        _ => unreachable!("subcommand_required is true"),
    }
}
