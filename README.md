password_manager_rs
======
A simple CLI (for now) password manager written in Rust

# Warning
## Currently this application does not supports database passwords longer than 16 characters

## Installation
* Clone this repo
* Run ```cargo build```

## Usage
```
./password_manager_rs new <DATABASE> - creates a new password database
./password_manager_rs open <DATABASE> - opens a database for inserting/editing/viewing/deleting entries
```
