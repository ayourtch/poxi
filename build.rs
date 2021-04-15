// Created with https://github.com/ayourtch/my-rust-boilerplate/

use std::env;

fn main() {
    use std::process::Command;

    let describe_output = Command::new("git")
        .arg("describe")
        .arg("--all")
        .arg("--long")
        .output()
        .unwrap();

    let mut describe = String::from_utf8_lossy(&describe_output.stdout).to_string();
    describe.pop();

    println!("cargo:rustc-env=GIT_VERSION=version {}", &describe);
}
