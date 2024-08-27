pub fn to_hex_str<T>(bytes: &T) -> String
where
    T: AsRef<[u8]> + ?Sized,
{
    let x = bytes.as_ref();

    x.iter()
        .map(|v| format!("{:02x}", v))
        .collect::<Vec<String>>()
        .join("")
}
