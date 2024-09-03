use std::error::Error;

use pe_sign::PeSign;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("./examples/pkcs7.cer");
    let pesign = PeSign::from_certificate_table_buf(bytes)?;

    for cert in pesign.get_certificate_chains()?[0].iter() {
        println!("subject: {}", cert.subject);
        println!("issuer:  {}", cert.issuer);
        println!();
    }

    // println!("{:?}", pesign.get_certificate_chains()?);

    Ok(())
}
