extern crate argonautica;
extern crate block_modes;
extern crate clap;
extern crate serde;
extern crate termion;
extern crate toml;
extern crate twofish;
extern crate rand;

mod password_database;

use password_database::PasswordDatabase;
use argonautica::Hasher;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{App, Arg, SubCommand};
use std::env::var_os;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::{stdin, stdout};
use std::path::PathBuf;
use termion::input::TermRead;
use twofish::Twofish;
use rand::prelude::*;


type TwofishCbc = Cbc<Twofish, Pkcs7>;

fn create_password() -> String {
    let acceptable_characters = "abcdefghijklmnopqrstuvwxyz\
                                ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                01234567890!$%^*.+-";
    let mut rng = thread_rng(); // Probably good enough
    let mut pass = String::new();
    for _ in 0 .. 18 { // Maybe make length variable
        pass.push(acceptable_characters.chars().choose(&mut rng).unwrap());
    }
    pass
}

fn password_encrypt(id: &str, pw: &str, db_password: &str) -> Vec<u8> {
    let mut bytes = id.as_bytes().to_owned();
    while bytes.len() < 16 {
        bytes.push(0);
    }

    let mut key = db_password.as_bytes().to_owned();
    while key.len() < 16 {
        key.push(0);
    }

    let cipher = TwofishCbc::new_var(&key, &bytes).unwrap(); // TODO: Max key length is only 16 - need to fix it
    cipher.encrypt_vec(pw.as_bytes())
}

fn password_decrypt(id: &str, pw: &[u8], db_password: &str) -> String {
    let mut bytes = id.as_bytes().to_owned();
    while bytes.len() < 16 {
        bytes.push(0);
    }

    let mut key = db_password.as_bytes().to_owned();
    while key.len() < 16 {
        key.push(0);
    }

    let cipher = TwofishCbc::new_var(&key, &bytes).unwrap();
    let pw_bytes = cipher.decrypt_vec(pw).unwrap();
    String::from_utf8(pw_bytes).unwrap()
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
                        println!("Entry added successfully");
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
                let pw = create_password();
                let cipher_pw = password_encrypt(&id, &pw, db_pw);
                match db.add(&id, cipher_pw) {
                    Ok(_) => {
                        println!("Your new password is: {}", pw); // TODO: clear screen after showing password
                        println!("Entry added successfully");
                    },
                    Err(_) => {
                        println!("Entry with id {} already exists", id);
                    }
                }
            }
            3 => {
                print!("login: ");
                stdout().flush().unwrap();
                let mut id = String::new();
                stdin().read_line(&mut id)?;
                id = id.trim().to_owned();
                match db.get(&id) {
                    Some(enc_pw) => {
                        let dec_pw = password_decrypt(&id, &enc_pw, db_pw);
                        println!("password: {}", dec_pw); // TODO: clear screen after showing password
                    },
                    None => {
                        println!("Entry not found");
                    }
                }
            }
            4 => {
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
            5 => {
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
         2 - Add an entry with generated password\r\n\
         3 - View an entry\r\n\
         4 - Delete an entry\r\n\
         5 - Edit an entry\r\n\
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

            match PasswordDatabase::open_db(db_path, &db_password) {
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
