use std::error::Error;

use pe_sign::PeSign;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("./examples/pkcs7.cer");
    let pesign = PeSign::from_certificate_table_buf(bytes)?;

    println!("{:?}", pesign);

    Ok(())
}