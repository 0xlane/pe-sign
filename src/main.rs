use std::error::Error;

use pe_sign::parse_pkcs7;

fn main() -> Result<(), Box<dyn Error>> {
    let bytes = include_bytes!("./examples/pkcs7.cer");
    parse_pkcs7(bytes)?;

    Ok(())
}