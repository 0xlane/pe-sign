use std::error::Error;

use pe_sign::PeSign;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("./examples/pkcs7.cer");
    let pesign = PeSign::from_certificate_table_buf(bytes)?;

    for cert in &pesign.signer_cert_chain[..] {
        println!("subject: {}", cert.subject);
        println!("issuer:  {}", cert.issuer);
        println!("issuer:  {}", cert.subject_public_key_info.algorithm);
        println!();
    }

    let trusted = pesign.signer_cert_chain.is_trusted()?;
    println!("{}", trusted);

    let status = pesign.verify_signer()?;
    println!("{:?}", status);

    Ok(())
}
