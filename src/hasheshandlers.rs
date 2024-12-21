use crate::{rhai_err, Error, Result, RhaiRes};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use bcrypt::{hash, DEFAULT_COST};

#[derive(Clone, Debug)]
pub struct Argon {
    salt: SaltString,
    argon: Argon2<'static>,
}
impl Default for Argon {
    fn default() -> Self {
        Self::new()
    }
}

impl Argon {
    #[must_use]
    pub fn new() -> Self {
        Self {
            salt: SaltString::generate(&mut OsRng),
            argon: Argon2::default(),
        }
    }

    pub fn hash(&self, password: String) -> Result<String> {
        Ok(self
            .argon
            .hash_password(password.as_bytes(), &self.salt)
            .map_err(Error::Argon2hash)?
            .to_string())
    }

    pub fn rhai_hash(&mut self, password: String) -> RhaiRes<String> {
        self.hash(password).map_err(rhai_err)
    }
}

pub fn bcrypt_hash(password: String) -> Result<String> {
    hash(&password, DEFAULT_COST).map_err(Error::BcryptError)
}
