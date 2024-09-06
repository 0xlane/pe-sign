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

pub trait VecInto<D> {
    fn vec_into(self) -> Vec<D>;
}

impl<E, D> VecInto<D> for Vec<E>
where
    D: From<E>,
{
    fn vec_into(self) -> Vec<D> {
        self.into_iter().map(std::convert::Into::into).collect()
    }
}

pub trait TryVecInto<D> {
    fn try_vec_into(self) -> Result<Vec<D>, Box<dyn std::error::Error>>;
}

impl<E, D> TryVecInto<D> for Vec<E>
where
    D: TryFrom<E>,
    <D as TryFrom<E>>::Error: std::error::Error + 'static,
{
    fn try_vec_into(self) -> Result<Vec<D>, Box<dyn std::error::Error>> {
        let mut x = vec![];

        for i in self {
            x.push(i.try_into()?);
        }

        Ok(x)
    }
}

pub trait OptionInto<D> {
    fn opt_into(self) -> Option<D>;
}

impl<E, D> OptionInto<D> for Option<E>
where
    D: From<E>,
{
    fn opt_into(self) -> Option<D> {
        self.and_then(|v| Some(v.into()))
    }
}

pub trait OptionVecInto<D> {
    fn opt_vec_into(self) -> Option<Vec<D>>;
}

impl<E, D> OptionVecInto<D> for Option<Vec<E>>
where
    D: From<E>,
{
    fn opt_vec_into(self) -> Option<Vec<D>> {
        self.and_then(|v| Some(v.vec_into()))
    }
}

pub trait IndentString {
    fn indent(self, size: u8) -> String;
}

impl<T> IndentString for T
where
    T: AsRef<str>,
{
    fn indent(self, size: u8) -> String {
        let mut result = String::new();
        for line in self.as_ref().lines() {
            result.push_str((" ".repeat(size as _) + line + "\n").as_str());
        }
        result.trim_end().to_owned()
    }
}

pub trait DisplayBytes {
    fn to_string(self) -> String;
}

impl<T> DisplayBytes for T
where
    T: AsRef<[u8]>,
{
    fn to_string(self) -> String {
        const LINE_SIZE: usize = 18;
        #[cfg(target_os = "windows")]
        const NEWLINE: &str = "\r\n";

        #[cfg(not(target_os = "windows"))]
        const NEWLINE: &str = "\n";

        let mut result = String::new();

        for (index, value) in self.as_ref().iter().enumerate() {
            if index != 0 && index % LINE_SIZE == 0 {
                result.push_str(NEWLINE);
            }

            result.push_str(format!("{:02x}:", value).as_str());
        }

        result
            .trim_end_matches(|v| v == ':' || v == '\n')
            .to_owned()
    }
}
