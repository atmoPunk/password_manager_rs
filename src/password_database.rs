use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::io::{Read, Write};
use argonautica::Verifier;
use std::error::Error;
use std::env::var_os;

type ByteVec = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordDatabase {
    pub main_hash: String,
    pub path: PathBuf,
    pub passwords: Option<HashMap<String, ByteVec>>,
}

impl PasswordDatabase {
    pub fn get(&self, id: &str) -> Option<ByteVec> {
        match &self.passwords {
            Some(passwords) => passwords.get(id).cloned(),
            None => None,
        }
    }

    pub fn add(&mut self, id: &str, pw: ByteVec) -> Result<(), ()> {
        match self.passwords {
            Some(ref mut passwords) => {
                match passwords.get(id) {
                    Some(_) => Err(()),
                    None => {
                        passwords.insert(id.to_owned(), pw);
                        self.write();
                        Ok(())
                    }
                }
            }
            None => {
                let mut hm = HashMap::new();
                hm.insert(id.to_owned(), pw);
                self.passwords = Some(hm);
                self.write();
                Ok(())
            }
        }
    }

    fn write(&self) {
        let toml = toml::to_string(self).expect("Cant convert to toml");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(self.path.clone())
            .unwrap(); // TODO: do not rewrite file every time (SQLite)
        file.write_all(toml.as_bytes()).unwrap();
    }

    pub fn delete(&mut self, id: &str) -> Result<(), ()> {
        match self.passwords {
            Some(ref mut passwords) => {
                match passwords.remove_entry(id) {
                    Some((_, _)) => { self.write(); Ok(()) },
                    None => Err(())
                }
            },
            None => Err(())
        }
        
    }

    pub fn edit(&mut self, id: &str, pw: ByteVec) -> Result<(), ()> {
        match self.passwords {
            Some(ref mut passwords) => {
                match passwords.get(id) {
                    Some(_) => { passwords.insert(id.to_owned(), pw); self.write(); Ok(()) },
                    None => {
                        Err(())
                    }
                }
            }

            None => {
                Err(())
            }
        }
    }

    pub fn open_db(db: &str, pw: &str) -> Result<PasswordDatabase, Box<dyn Error>> {
        let mut file = File::open(db)?;
        let mut bytes: Vec<u8> = Default::default();
        file.read_to_end(&mut bytes)?;
        let pd: PasswordDatabase = toml::from_slice(&bytes)?;
        let mut verifier = Verifier::default();
        let is_valid = verifier
            .with_hash(pd.main_hash.clone())
            .with_password(pw)
            .with_secret_key(var_os("USER").unwrap().into_string().unwrap())
            .verify()
            .unwrap();
        if is_valid {
            Ok(pd)
        } else {
            Err(Box::new(PasswordError {
                password: pw.to_owned(),
            }))
        }
    }
}

#[derive(Debug)]
struct PasswordError {
    password: String,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password Error {}", self.password)
    }
}

impl Error for PasswordError {
    fn description(&self) -> &str {
        "Wrong password"
    }
}