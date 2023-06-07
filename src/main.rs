#![feature(absolute_path)]
use clap::Parser;
use jars::JarOptionBuilder;
use std::path::{absolute, Path};

#[derive(Parser, Debug)]
struct ModSus {
    #[arg()]
    path: String,
    #[arg(long, short = 'v')]
    verbose: bool,
    #[arg(long)]
    show_file_content: bool,
}

fn main() {
    let sus = [
        "ClassLoader",
        "%(Ljava/lang/String;)Ljava/lang/Class",
        "ClassforName",
    ];
    let cli = ModSus::parse();

    macro_rules! verbose_println {
        ($fmt:expr $(, $($arg:expr),*)?) => {
            if cli.verbose {
                println!($fmt $(, $($arg),*)?);
            }
        };
    }
    println!("This tool **will** detect false positives, and maybe even false negatives. Do not treat a yes/no from this tool as a certain on either side, use it as guidance.");
    verbose_println!("verbose mode enabled");
    verbose_println!("provided path: {}", cli.path);
    let binding = absolute(Path::new(&cli.path)).unwrap();
    let path = binding.as_path();
    println!("path: {}", path.display());
    if !path.is_file() {
        panic!("argument PATH is not a file")
    }
    if !path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .ends_with(".jar")
        && !path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with(".zip")
    {
        panic!("file extension is not .jar or .zip")
    }
    let jar = jars::jar(path, JarOptionBuilder::default()).unwrap();
    let mut suspicious = false;
    for (file_path, content) in jar.files {
        println!("scanning: {}", file_path);
        let mut file_content = "error: unsafe block did not run";
        unsafe {
            file_content = std::str::from_utf8_unchecked(&content);
        }
        if cli.show_file_content {
            println!("file.content: {}", file_content);
        }
        for item in sus {
            println!("checking for: {}", item);
            if file_content.contains(item) {
                suspicious = true;
                println!("found {} in {}", item, file_path)
            }
        }
    }
    println!("--------------------------------------------------------------------------------");
    if suspicious {
        println!("THIS FILE MAY NOT BE SAFE. TAKE CAUTION.")
    } else {
        println!("Nothing suspicious was detected. This file may still not be safe, take caution.")
    }
    println!("--------------------------------------------------------------------------------");
}
