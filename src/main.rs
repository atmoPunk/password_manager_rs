extern crate argonautica;
extern crate clap;
extern crate toml;
extern crate serde;
extern crate twofish;
extern crate block_modes;
extern crate termion;


use termion::input::TermRead;
use std::io::{stdin, stdout};
use argonautica::{Hasher, Verifier};
use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::io::prelude::*;
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::collections::HashMap;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::env::var_os;
use twofish::Twofish;

type TwofishCbc = Cbc<Twofish, Pkcs7>;
type ByteVec = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
struct PasswordDatabase {
    main_hash: String,
    passwords: Option<HashMap<String, ByteVec>>,
}

impl PasswordDatabase {
    fn get(&self, id: &str) -> Option<ByteVec> {
        match &self.passwords {
            Some(passwords) => {
                passwords.get(id).cloned()
            },
            None => {
                None
            }
        }
    }

    fn add(&mut self, id: String, pw: ByteVec) {
        match self.passwords {
            Some(ref mut passwords) => {
                passwords.insert(id, pw);
            },
            None => {
                let mut hm = HashMap::new();
                hm.insert(id, pw);
                self.passwords = Some(hm);
            }
        }
    }
    
    fn delete(&mut self, id: &str) {
        unimplemented!();
    }
}

fn password_encrypt(id: &str, pw: &str, db_password: &str) -> Vec<u8> {
    let mut bytes = (id.to_owned() + var_os("USER").unwrap().to_str().unwrap()).as_bytes().to_owned();
    while bytes.len() < 16 {
        bytes.append(&mut bytes.clone());
    }

    let mut key = db_password.as_bytes().to_owned();
    while key.len() < 16 {
        key.append(&mut key.clone());
    }

    let cipher = TwofishCbc::new_var(&key[0 .. 16], &bytes[0 .. 16]).unwrap();
    cipher.encrypt_vec(pw.as_bytes())
}

fn password_decrypt(id: &str, pw: &[u8], db_password: &str) -> String {
    let mut bytes = (id.to_owned() + var_os("USER").unwrap().to_str().unwrap()).as_bytes().to_owned();
    while bytes.len() < 32 {
        bytes.append(&mut bytes.clone());
    }

    let mut key = db_password.as_bytes().to_owned();
    while key.len() < 16 {
        key.append(&mut key.clone());
    }

    let cipher = TwofishCbc::new_var(&key[0 .. 16], &bytes[0 .. 16]).unwrap();
    let pw_bytes = cipher.decrypt_vec(pw).unwrap();
    String::from_utf8(pw_bytes).unwrap()
}

#[derive(Debug)]
struct PasswordError {
    password: String
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
                .verify().unwrap();
    if is_valid {
        Ok(pd)
    } else {
        Err(Box::new(PasswordError { password: pw.to_owned() } ))
    }
}

// TODO: add writing again

fn db_menu(db: &mut PasswordDatabase, db_pw: &str) -> Result<(), Box<dyn Error>> {
    let mut buffer = String::new();
    print!("{}", menu_string());
    
    loop {
        stdin().read_line(&mut buffer)?;
        println!("buffer is {:?}", buffer);
        let option = buffer.trim().parse::<i32>()?;
        buffer.clear();
        println!("option is {}", option);
        match option {
            0 => break,
            1 => {
                let (id, pw) = read_entry()?;
                let cipher_pw = password_encrypt(&id, &pw, db_pw);
                db.add(id.to_owned(), cipher_pw);
                println!("DB is now {:?}", db);
            },
            2 => {
                let mut id = String::new();
                stdin().read_line(&mut id)?;
                id = id.trim().to_owned();
                match db.get(&id) {
                    Some(enc_pw) => {
                        let dec_pw = password_decrypt(&id, &enc_pw, db_pw);
                        println!("{}:\n{}", id, dec_pw);
                    },
                    None => {
                        println!("password with id \"{}\" not found", id);
                    }
                }
            }
            3 => {
                let mut id = String::new();
                stdin().read_line(&mut id)?;
                db.delete(&id);
            }
            _ => ()
        }
        print!("{}", menu_string());
    }
    Ok(())
}

fn read_entry() -> Result<(String, String), Box<dyn Error>> {
    let stdout = stdout();
    let mut stdout = stdout.lock();

    let stdin = stdin();
    let mut stdin = stdin.lock();

    let id = TermRead::read_line(&mut stdin)?.unwrap();
    let pass = stdin.read_passwd(&mut stdout)?.unwrap();
    println!("Password read!");

    Ok((id, pass))
}

fn menu_string() -> String {
    format!("1 - Add an entry\r\n\
             2 - View an entry\r\n\
             3 - Delete an entry\r\n\
             0 - Exit\r\n")
} 

fn main() {
    let matches = App::new("Password Manager")
                        .version("0.1")
                        .author("Dmitriy I. <atmopunk@outlook.com>")
                        .about("Stores passwords")
                        .subcommand(SubCommand::with_name("create")
                            .about("creates a new password database")
                            .arg(Arg::with_name("DATABASE")
                                .help("File in which passwords are stored")
                                .required(true)
                                .index(1))
                            .arg(Arg::with_name("PASSWORD")
                                .help("Password to lock database with")
                                .required(true)
                                .index(2)))
                        .subcommand(SubCommand::with_name("open")
                            .about("opens a database")
                            .arg(Arg::with_name("DATABASE")
                                .help("File in which passwords are stored")
                                .required(true)
                                .index(1))
                            .arg(Arg::with_name("PASSWORD")
                                .help("Password to open database with")
                                .required(true)
                                .index(2)) )
                            // .subcommand(SubCommand::with_name("add")
                            //     .about("add a password to database")
                            //     .arg(Arg::with_name("PASSWORD_ID")
                            //         .help("login/site name/whatever")
                            //         .required(true)
                            //         .index(1))
                            //     .arg(Arg::with_name("NEW_PASSWORD")
                            //         .help("password to add")
                            //         .required(true)
                            //         .index(2)))
                            // .subcommand(SubCommand::with_name("get")
                            //     .about("get a password from database")
                            //     .arg(Arg::with_name("PASSWORD_ID")
                            //         .help("login/site name/whatever")
                            //         .required(true)
                            //         .index(1))))
                        .get_matches();

    match matches.subcommand() {
        ("create", create_matches) => {
            let create_matches = create_matches.unwrap();
            let db = create_matches.value_of("DATABASE").unwrap();
            let password = create_matches.value_of("PASSWORD").unwrap();
            let mut hasher = Hasher::default();
            let pw_hash = hasher.with_password(password)
                                .with_secret_key(var_os("USER").unwrap().into_string().unwrap())
                                .hash()
                                .unwrap();
            let pd = PasswordDatabase {
                main_hash: pw_hash,
                passwords: None
            };

            let toml = toml::to_string(&pd).unwrap();
            let mut db_file = File::create(db).expect("Can't create a database file");
            db_file.write_all(toml.as_bytes()).unwrap();
        },
        ("open", open_matches) => {
            let open_matches = open_matches.unwrap();
            let db_path = open_matches.value_of("DATABASE").unwrap();
            let db_password = open_matches.value_of("PASSWORD").unwrap();
            let mut db = open_db(db_path, db_password).unwrap();
            db_menu(&mut db, db_password).unwrap();
            // match open_matches.subcommand() {
            //     ("add", add_matches) => {
            //         let add_matches = add_matches.unwrap();
            //         let pw_id = add_matches.value_of("PASSWORD_ID").unwrap();
            //         let new_pw = add_matches.value_of("NEW_PASSWORD").unwrap();
            //         let cipher_pw = password_encrypt(pw_id, new_pw, db_password);
            //         db.add(pw_id.to_owned(), cipher_pw);
            //         let toml = toml::to_string(&db).unwrap();
            //         let mut db_file = File::create(db_path).expect("Can't create a database file");
            //         db_file.write_all(toml.as_bytes()).unwrap();
            //     },
            //     ("get", get_matches) => {
            //         let get_matches = get_matches.unwrap();
            //         let pw_id = get_matches.value_of("PASSWORD_ID").unwrap();
            //         match db.get(pw_id) {
            //             Some(enc_pw) => {
            //                 let dec_pw = password_decrypt(pw_id, &enc_pw, db_password);
            //                 println!("{}:\n{}", pw_id, dec_pw);
            //             },
            //             None => {
            //                 println!("password with id \"{}\" not found", pw_id);
            //             }
            //         }
            //     }
            //     _ => {}
            // }
        },
        _ => {}
    }
}
