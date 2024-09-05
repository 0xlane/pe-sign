use std::error::Error;

use pe_sign::PeSign;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("./examples/pkcs7.cer");
    let pesign = PeSign::from_certificate_table_buf(bytes)?;

    for cert in &pesign.signed_data.signer_cert_chain[..] {
        println!("subject: {}", cert.subject);
        println!("issuer:  {}", cert.issuer);
        println!("issuer:  {}", cert.subject_public_key_info.algorithm);
        println!();
    }

    let trusted = pesign.signed_data.signer_cert_chain.is_trusted()?;
    println!("{}", trusted);

    let status = pesign.verify()?;
    println!("{:?}", status);

    let cs_cert_chain = pesign.signed_data.build_contersignature_cert_chain()?.unwrap();

    for cert in &cs_cert_chain[..] {
        println!("subject: {}", cert.subject);
        println!("issuer:  {}", cert.issuer);
        println!("issuer:  {}", cert.subject_public_key_info.algorithm);
        println!();
    }

    Ok(())
}
