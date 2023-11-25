//! # Transitions' password type
//!
//! `tag_password` is an simple Rust library designed to enhance security by leveraging the type system to
//! statically determine password hashing status. This approach ensures a clear distinction between plain text
//! and hashed passwords in your code, allowing for stronger security measures.
//!
//! ## Features
//!
//! - **Type-based Password Markers:** Two marker types, Hashed and Plain, are used to distinguish between
//!   hashed and plain text passwords. These zero-sized types, combined with PhantomData, facilitate compile-time
//!   checks for password status.
//!
//! - **Argon2 Hashing (Optional):** If the argon2 feature is enabled, the library provides hashing functionality
//!   using Argon2, a secure password hashing algorithm.
//!
//! ## Usage
//!
//! Add the library to your current project using Cargo:
//!
//! ```sh
//! cargo add tag_password
//! ```
//!
//! Then create a new password and operate on them
//!
//! ```rust
//! use tag_password::Password;
//! use argon2::password_hash::SaltString;
//! use rand_core::OsRng;
//!
//! // Create a new plain text password
//! let salt = SaltString::generate(&mut OsRng);
//! let plain_password = Password::new("my_password");
//! // Hash the plain text password using Argon2
//! let hashed_password = plain_password
//!     .hash(None, &salt)
//!     .expect("Hashing should not fail.");
//! // Verify a hashed password against a plain text password
//! hashed_password
//!     .verify(None, plain_password)
//!     .expect("Verification should not fail.");
//! ```
//!
//! ## License
//!
//! This project is licensed under the [MIT License](LICENSE).

#[cfg(feature = "argon2")]
use argon2::{password_hash::Salt, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
#[cfg(feature = "graphql")]
use async_graphql::{registry::MetaType, registry::MetaTypeId, registry::Registry, InputType};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
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
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Password<T: ?Sized>(PhantomData<T>, String);

impl<T: ?Sized> Password<T> {
    /// Creates a new `Password` instance from the provided value.
    ///
    /// # Arguments
    ///
    /// * `value`: A value that can be converted into a `String`.
    ///
    /// Returns a new `Password` instance with the provided value.
    pub fn new(value: impl Into<String>) -> Self {
        Password(Default::default(), value.into())
    }

    /// Retrieves the byte representation of the password value.
    ///
    /// Returns a slice containing the bytes representing the password.
    pub fn as_bytes(&self) -> &[u8] {
        self.1.as_bytes()
    }
}

impl Password<Plain> {
    /// Converts a plain text password into a hashed password.
    ///
    /// Returns a new `Password` instance containing the hashed password.
    pub unsafe fn as_hashed(self) -> Password<Hashed> {
        Password::new(self.1)
    }

    /// Hashes the password using Argon2 (if the 'argon2' feature is enabled).
    ///
    /// - `argon2`: An optional `Argon2` configuration.
    /// - `salt`: A salt value used for hashing.
    ///
    /// Produces a result containing a new `Password` instance with the hashed value if successful.
    /// If hashing fails, an `argon2::password_hash::Result` with an error is returned.
    #[cfg(feature = "argon2")]
    pub fn hash<'a>(
        &self,
        argon2: Option<Argon2>,
        salt: impl Into<Salt<'a>>,
    ) -> argon2::password_hash::Result<Password<Hashed>> {
        let v = self.1.as_bytes();
        Ok(Password::new(
            argon2
                .unwrap_or_default()
                .hash_password(v, salt)?
                .to_string(),
        ))
    }
}

impl Password<Hashed> {
    /// Unsafely converts a hashed password into a plain text password.
    /// This operation is marked as unsafe because once a password is hashed,
    /// it cannot be converted back to plain text.
    ///
    /// Returns a new `Password` instance containing the plain text password.
    pub unsafe fn as_plain(self) -> Password<Plain> {
        Password::new(self.1)
    }

    /// Verifies if the hashed password matches the provided plain text password.
    ///
    /// - `argon2`: An optional `Argon2` configuration.
    /// - `plain`: A plain text password used for verification.
    ///
    /// Returns a result indicating success or failure of the verification process.
    /// If successful, `Ok(())` is returned. If verification fails, an
    /// `argon2::password_hash::Result` with an error is returned.

    pub fn verify(
        &self,
        argon2: Option<Argon2>,
        plain: impl Into<Password<Plain>>,
    ) -> argon2::password_hash::Result<()> {
        argon2
            .unwrap_or_default()
            .verify_password(plain.into().as_bytes(), &PasswordHash::new(&self.1)?)
    }
}

impl<T: ?Sized> Into<String> for Password<T> {
    /// Converts the `Password` instance into a `String`.
    fn into(self) -> String {
        self.1
    }
}

#[cfg(feature = "graphql")]
impl<T: ?Sized + Send + Sync> InputType for Password<T> {
    type RawValueType = String;

    fn type_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Password")
    }

    fn create_type_info(registry: &mut Registry) -> String {
        registry.create_input_type::<Password<T>, _>(MetaTypeId::Scalar, |_| MetaType::Scalar {
            name: "Password".into(),
            description: Some("A type used internally to represent a password.".into()),
            is_valid: None,
            visible: None,
            inaccessible: false,
            tags: Default::default(),
            specified_by_url: None,
        })
    }

    fn parse(value: Option<async_graphql::Value>) -> async_graphql::InputValueResult<Self> {
        if value.is_none() {
            return Err("A password must have a value.".into());
        }

        match value.unwrap() {
            async_graphql::Value::String(text) => Ok(Password::new(text)),
            _ => Err("A password must be a String.".into()),
        }
    }

    fn to_value(&self) -> async_graphql::Value {
        async_graphql::Value::String(self.1.clone())
    }

    fn as_raw_value(&self) -> Option<&Self::RawValueType> {
        Some(&self.1)
    }
}

impl<T: ?Sized> From<String> for Password<T> {
    /// Converts the `String` instance to a `Password`.
    fn from(value: String) -> Self {
        Password(Default::default(), value)
    }
}

impl<T: ?Sized> Debug for Password<T> {
    /// Formats the `Password` for debugging purposes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.1)
    }
}

impl<T: ?Sized> Display for Password<T> {
    /// Formats the `Password` for displaying purposes.
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
    fn argon_encoding_decoding() {
        let plain_password = Password::new("Password");
        let salt = SaltString::generate(&mut OsRng);

        let argon_encoded_password = plain_password
            .hash(None, &salt)
            .expect("Argon2 encoding should not fail.");

        argon_encoded_password
            .verify(None, plain_password)
            .expect("Argon2 encoded password verification should not fail.");
    }
}
