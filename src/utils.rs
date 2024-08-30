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
