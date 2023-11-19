# Transitions' password type

`tag_password` is an simple Rust library designed to enhance security by leveraging the type system to statically determine password hashing status. This approach ensures a clear distinction between plain text and hashed passwords in your code, allowing for stronger security measures.

## Features

- **Type-based Password Markers:** Two marker types, Hashed and Plain, are used to distinguish between hashed and plain text passwords. These zero-sized types, combined with PhantomData, facilitate compile-time checks for password status.

**Argon2 Hashing (Optional):** If the argon2 feature is enabled, the library provides hashing functionality using Argon2, a secure password hashing algorithm.

## Usage

Add the library to your current project using Cargo:
```sh
cargo add tag_password
```

Then create a new password and operate on them
```rust
use tag_password::Password;

// Create a new plain text password
let plain_password = Password::new("my_password");
// Hash the plain text password using Argon2
let hashed_password = plain_password
    .hash(None, &salt)
    .expect("Hashing should not fail.");
// Verify a hashed password against a plain text password
hashed_password
    .verify(None, plain_password)
    .expect("Verification should not fail.");
```

## License

This project is licensed under the [MIT License](LICENSE).
