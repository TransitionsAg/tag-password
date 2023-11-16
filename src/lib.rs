use argon2::PasswordHash;
#[cfg(feature = "argon2")]
use argon2::{
    password_hash::{Error, Result, Salt},
    Argon2, PasswordHasher,
};
use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

/// Marker type indicating a hashed password.
///
/// This struct is used as a marker to indicate whether a password has been hashed or not.
/// It serves as a zero-sized type without any fields, consuming no memory at runtime.
/// When paired with `PhantomData`, it enables compile-time checks to distinguish
/// between hashed and non-hashed password types.
pub struct Hashed;

/// Marker type indicating a plain text password.
///
/// This struct is used as a marker to indicate that a password is in plain text,
/// distinguishing it from hashed passwords. Similar to `Hashed`, `Plain` is a
/// zero-sized type without any fields, consuming no memory at runtime.
/// When paired with `PhantomData`, it enables compile-time checks to differentiate
/// between plain text and hashed password types.
pub struct Plain;

/// Represents password data that can be hashed and verified.
///
/// This struct encapsulates password data and supports hashing with the `hash` function,
/// which can be enabled with the `argon2` feature. It also provides verification
/// functionality via the `verify` function.
pub struct Password<T: ?Sized>(PhantomData<T>, String);

impl<T: ?Sized> Password<T> {
    pub fn new(value: impl Into<String>) -> Self {
        Password(Default::default(), value.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.1.as_bytes()
    }
}

impl Password<Plain> {
    pub fn as_hashed(self) -> Password<Hashed> {
        Password::new(self.1)
    }

    #[cfg(feature = "argon2")]
    pub fn hash<'a>(
        self,
        argon2: Option<Argon2>,
        salt: impl Into<Salt<'a>>,
    ) -> Result<Password<Hashed>> {
        let v = self.1.as_bytes();
        Ok(Password::new(
            argon2
                .unwrap_or_default()
                .hash_password(v, salt)?
                .hash
                .ok_or(Error::Password)?
                .to_string(),
        ))
    }
}

impl Password<Hashed> {
    pub fn as_plain(self) -> Password<Plain> {
        Password::new(self.1)
    }

    pub fn verify(argon2: Option<Argon2>, plain: impl Into<Password<Plain>>) {
        // TODO
    }
}

impl<T: ?Sized> Into<String> for Password<T> {
    fn into(self) -> String {
        self.1
    }
}

impl<T: ?Sized> Debug for Password<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.1)
    }
}

impl<T: ?Sized> Display for Password<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.1)
    }
}

#[cfg(test)]
mod tests {
    use argon2::password_hash::SaltString;
    use rand_core::OsRng;

    use crate::Password;

    #[test]
    fn argon_encoding() {
        let plain_password = Password::new("AZDAIZDIAZNDAIZDNIAZDNIAZD");
        let salt = SaltString::generate(&mut OsRng);
        let argon_encoded_password = plain_password
            .hash(None, &salt)
            .expect("Argon2 encoding should not fail.");
        println!("{}", argon_encoded_password)
    }
}
