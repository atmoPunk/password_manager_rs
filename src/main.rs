extern crate argonautica;
extern crate block_modes;
extern crate clap;
extern crate serde;
extern crate termion;
extern crate toml;
extern crate twofish;

use argonautica::{Hasher, Verifier};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env::var_os;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{stdin, stdout};
use std::path::PathBuf;
use termion::input::TermRead;
use twofish::Twofish;

type TwofishCbc = Cbc<Twofish, Pkcs7>;
type ByteVec = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
struct PasswordDatabase {
    main_hash: String,
    path: PathBuf,
    passwords: Option<HashMap<String, ByteVec>>,
}

impl PasswordDatabase {
    fn get(&self, id: &str) -> Option<ByteVec> {
        match &self.passwords {
            Some(passwords) => passwords.get(id).cloned(),
            None => None,
        }
    }

    fn add(&mut self, id: &str, pw: ByteVec) -> Result<(), ()> {
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
            .unwrap(); // TODO: do not rewrite file every time
        file.write_all(toml.as_bytes()).unwrap();
    }

    fn delete(&mut self, id: &str) -> Result<(), ()> {
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

    fn edit(&mut self, id: &str, pw: ByteVec) -> Result<(), ()> {
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
}

fn password_encrypt(id: &str, pw: &str, db_password: &str) -> Vec<u8> {
    let mut bytes = (id.to_owned() + var_os("USER").unwrap().to_str().unwrap())
        .as_bytes()
        .to_owned();
    while bytes.len() < 16 {
        bytes.append(&mut bytes.clone());
    }

    let mut key = db_password.as_bytes().to_owned();
    while key.len() < 16 {
        key.append(&mut key.clone());
    }

    let cipher = TwofishCbc::new_var(&key[0..16], &bytes[0..16]).unwrap();
    cipher.encrypt_vec(pw.as_bytes())
}

fn password_decrypt(id: &str, pw: &[u8], db_password: &str) -> String {
    let mut bytes = (id.to_owned() + var_os("USER").unwrap().to_str().unwrap())
        .as_bytes()
        .to_owned();
    while bytes.len() < 32 {
        bytes.append(&mut bytes.clone());
    }

    let mut key = db_password.as_bytes().to_owned();
    while key.len() < 16 {
        key.append(&mut key.clone());
    }

    let cipher = TwofishCbc::new_var(&key[0..16], &bytes[0..16]).unwrap();
    let pw_bytes = cipher.decrypt_vec(pw).unwrap();
    String::from_utf8(pw_bytes).unwrap()
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

fn open_db(db: &str, pw: &str) -> Result<PasswordDatabase, Box<dyn Error>> {
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

fn db_menu(db: &mut PasswordDatabase, db_pw: &str) -> Result<(), Box<dyn Error>> {
    let mut buffer = String::new();
    print!("{}", menu_string());

    loop {
        stdin().read_line(&mut buffer)?;
        let option = buffer.trim().parse::<i32>()?;
        buffer.clear();
        match option {
            0 => break,
            1 => {
                let (id, pw) = read_entry()?;
                let cipher_pw = password_encrypt(&id, &pw, db_pw);
                match db.add(&id, cipher_pw) {
                    Ok(_) => {
                        println!("Added successfully");
                    },
                    Err(_) => {
                        println!("Entry with id {} already exists", id);
                    }
                }
                
            }
            2 => {
                print!("login: ");
                stdout().flush().unwrap();
                let mut id = String::new();
                stdin().read_line(&mut id)?;
                id = id.trim().to_owned();
                match db.get(&id) {
                    Some(enc_pw) => {
                        let dec_pw = password_decrypt(&id, &enc_pw, db_pw);
                        println!("password: {}", dec_pw);
                    },
                    None => {
                        println!("Entry not found");
                    }
                }
            }
            3 => {
                let mut id = String::new();
                stdin().read_line(&mut id)?;
                match db.delete(&id) {
                    Ok(_) => {
                        println!("Entry deleted successfully");
                    },
                    Err(_) => {
                        println!("Entry not found");
                    }
                }
            }
            4 => {
                let (id, pw) = read_entry()?;
                let cipher_pw = password_encrypt(&id, &pw, db_pw);
                match db.edit(&id, cipher_pw) {
                    Ok(_) => {
                        println!("Edited successfully");
                    },
                    Err(_) => {
                        println!("Entry with id {} not found", id);
                    }
                }

            }
            _ => (),
        }
        print!("{}", menu_string());
    }
    Ok(())
}

fn read_password() -> Result<String, Box<dyn Error>> {
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let stdout = stdout();
    let mut stdout = stdout.lock();
    
    let pass = stdin.read_passwd(&mut stdout)?.unwrap();
    Ok(pass)
}

fn read_entry() -> Result<(String, String), Box<dyn Error>> {
    let id;
    let pass;
    
    {
        let stdin = stdin();
        let mut stdin = stdin.lock();

        print!("login: ");
        stdout().flush().unwrap();
        id = TermRead::read_line(&mut stdin)?.unwrap();
    }
    {
        print!("password: ");
        stdout().flush().unwrap();
        pass = read_password()?;
        println!("");
    }
    Ok((id, pass))
}

fn menu_string() -> String {
    String::from(
        "1 - Add an entry\r\n\
         2 - View an entry\r\n\
         3 - Delete an entry\r\n\
         4 - Edit an entry\r\n\
         0 - Exit\r\n",
    )
}

fn main() {
    let matches = App::new("Password Manager")
        .version("0.1")
        .author("Dmitriy I. <atmopunk@outlook.com>")
        .about("Stores passwords")
        .subcommand(
            SubCommand::with_name("new")
                .about("creates a new password database")
                .arg(
                    Arg::with_name("DATABASE")
                        .help("File in which passwords are stored")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("open")
                .about("opens a database")
                .arg(
                    Arg::with_name("DATABASE")
                        .help("File in which passwords are stored")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("new", create_matches) => {
            let create_matches = create_matches.unwrap();
            let db = create_matches.value_of("DATABASE").unwrap();

            let mut password;
            loop {
                print!("password: ");
                stdout().flush().unwrap();
                password = read_password().unwrap();
                print!("\npassword again: ");
                stdout().flush().unwrap();
                let password_re = read_password().unwrap();
                println!("");

                if password == password_re {
                    break;
                } else {
                    println!("Passwords do not match");
                }
            }
            
            let mut hasher = Hasher::default();
            let pw_hash = hasher
                .with_password(password)
                .with_secret_key(var_os("USER").unwrap().into_string().unwrap())
                .hash()
                .unwrap();

            let path = PathBuf::from(db);
            let mut path_parent = path.parent().expect("Wrong file").to_path_buf();
            if path_parent.to_str().unwrap().is_empty() {
                path_parent = std::env::current_dir().unwrap();
            }
            path_parent = path_parent.canonicalize().unwrap();
            let path = path_parent.join(path);

            let pd = PasswordDatabase {
                main_hash: pw_hash,
                passwords: None,
                path,
            };

            let toml = toml::to_string(&pd).unwrap();
            let mut db_file = File::create(db).expect("Can't create a database file");
            db_file.write_all(toml.as_bytes()).unwrap();
        }
        ("open", open_matches) => {
            let open_matches = open_matches.unwrap();
            let db_path = open_matches.value_of("DATABASE").unwrap();
            print!("password: ");
            stdout().flush().unwrap();
            let db_password = read_password().unwrap();
            println!("");

            match open_db(db_path, &db_password) {
                Ok(mut db) => {
                    db_menu(&mut db, &db_password).unwrap();
                },
                Err(_) => {
                    println!("Wrong password");
                }
            }
        }
        _ => {}
    }
}
