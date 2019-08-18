extern crate argonautica;
extern crate clap;
extern crate toml;
extern crate serde;

use argonautica::{Hasher, Verifier};
use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::io::prelude::*;
use serde::{Serialize, Deserialize};
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
struct Password {
    password_id: String,
    password_hash: String
}

#[derive(Debug, Serialize, Deserialize)]
struct PasswordDatabase {
    main_hash: String,
    passwords: Option<Vec<Password>>
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
    let mut file = File::open(db.to_owned() + ".toml")?;
    let mut bytes: Vec<u8> = Default::default();
    file.read_to_end(&mut bytes)?;
    let pd: PasswordDatabase = toml::from_slice(&bytes)?;
    let mut verifier = Verifier::default();
    let is_valid = verifier
                .with_hash(pd.main_hash.clone())
                .with_password(pw)
                .with_secret_key("secret_key")
                .verify().unwrap();
    if is_valid {
        Ok(pd)
    } else {
        Err(Box::new(PasswordError { password: pw.to_owned() } ))
    }
}

fn main() {
    let matches = App::new("Password Manager")
                        .version("0.0")
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
                                .index(2))
                            .subcommand(SubCommand::with_name("add")
                                .about("adds a password to database")
                                .arg(Arg::with_name("PASSWORD_ID")
                                    .help("login/site name/whatever")
                                    .required(true)
                                    .index(1))
                                .arg(Arg::with_name("NEW_PASSWORD")
                                    .help("password to add")
                                    .required(true)
                                    .index(2))))
                        .get_matches();

    match matches.subcommand() {
        ("create", create_matches) => {
            let create_matches = create_matches.unwrap();
            let db = create_matches.value_of("DATABASE").unwrap();
            let password = create_matches.value_of("PASSWORD").unwrap();
            let mut hasher = Hasher::default();
            let pw_hash = hasher.with_password(password)
                                .with_secret_key("secret_key")
                                .hash()
                                .unwrap();
            let pd = PasswordDatabase {
                main_hash: pw_hash,
                passwords: None
            };

            let toml = toml::to_string(&pd).unwrap();
            let mut db_file = File::create(db.to_owned() + ".toml").expect("Can't create a database file");
            db_file.write_all(toml.as_bytes()).unwrap();
        },
        ("open", open_matches) => {
            let open_matches = open_matches.unwrap();
            let db_path = open_matches.value_of("DATABASE").unwrap();
            let db_password = open_matches.value_of("PASSWORD").unwrap();
            let mut db = open_db(db_path, db_password).unwrap();
            match open_matches.subcommand() {
                ("add", add_matches) => {
                    let add_matches = add_matches.unwrap();
                    let pw_id = add_matches.value_of("PASSWORD_ID").unwrap();
                    let new_pw = add_matches.value_of("NEW_PASSWORD").unwrap();
                    let mut hasher = Hasher::default();
                    let pw_hash = hasher.with_password(new_pw)
                                        .with_secret_key("secret_key")
                                        .hash()
                                        .unwrap();
                    match db.passwords {
                        Some(ref mut passwords) => {
                            passwords.push(Password { 
                            password_id: pw_id.to_string(),
                            password_hash: pw_hash });
                        },
                        None => {
                            let mut passwords = Vec::new();
                            passwords.push(Password { 
                                password_id: pw_id.to_string(),
                                password_hash: pw_hash
                            });
                            db.passwords = Some(passwords)
                        }
                    };
                    let toml = toml::to_string(&db).unwrap();
                    let mut db_file = File::create(db_path.to_owned() + ".toml").expect("Can't create a database file");
                    db_file.write_all(toml.as_bytes()).unwrap();
                },
                _ => {}
            }
        },
        _ => {}
    }

    // let db = matches.value_of("DATABASE").unwrap();
    // let mut file = File::open(db)

    // let password = matches.value_of("DB PASSWORD").unwrap();
    // let mut hasher = Hasher::default();
    // let hash = hasher
    //             .with_password(password)
    //             .with_secret_key("secret_key")
    //             .with_salt("somesalt")
    //             .hash()
    //             .unwrap();
    // println!("Password is {}", password);
    // println!("Hash is {}", hash);
    // println!("Hello, world!");
}
