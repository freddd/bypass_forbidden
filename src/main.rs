use clap::{App, Arg, SubCommand};
use env_logger::Env;
use log::debug;
use regex::Regex;
use reqwest::Url;

mod brute_force;
mod bypass;

#[tokio::main]
async fn main() -> Result<(), ()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let matches = App::new("bypass_forbidden")
        .version("1.0")
        .author("freddd")
        .about("Tries to bypass 403 forbidden")
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .takes_value(true)
                .validator(validate_output),
        )
        .arg(
            Arg::with_name("url")
                .short("u")
                .long("url")
                .takes_value(true)
                .required(true)
                .validator(validate_url_prefix),
        )
        .arg(
            Arg::with_name("content-length")
                .short("cl")
                .takes_value(true)
                .long("content-length")
                .required(true),
        )
        .subcommand(
            SubCommand::with_name("bypass")
                .about("tries to bypass 403 forbidden by using different verbs, paths, headers"),
        )
        .subcommand(
            SubCommand::with_name("brute-force")
                .about(
                    "tries to bypass 403 forbidden by enumerating ips in range to brute force XFF",
                )
                .arg(
                    Arg::with_name("cidr")
                        .short("cidr")
                        .long("cidr")
                        .required(true)
                        .takes_value(true)
                        .validator(validate_cidr),
                ),
        )
        .get_matches();

    debug!("{:#?}", matches);

    let u = matches.value_of("url").unwrap();
    let url = Url::parse(u).unwrap();
    debug!("url: {:#?}", url);

    let content_length = matches
        .value_of("content-length")
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap();
    debug!("content-length: {:#?}", content_length);

    let output = matches.value_of("output").unwrap_or("table");
    debug!("output: {:#?}", output);

    match matches.subcommand() {
        ("bypass", Some(_)) => {
            let b = bypass::Bypass::new(url, content_length, output.to_string());
            b.scan().await;
        }
        ("brute-force", Some(args_matches)) => {
            let cidr_string = args_matches.value_of("cidr").unwrap();

            let bf =
                brute_force::BruteForce::new(url, content_length, output.to_string(), cidr_string);
            bf.scan().await;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn validate_url_prefix(val: std::string::String) -> Result<(), String> {
    if val.starts_with("http://") || val.starts_with("https://") {
        Ok(())
    } else {
        Err(String::from(
            "the url needs to start with http:// or https://",
        ))
    }
}

fn validate_cidr(val: std::string::String) -> Result<(), String> {
    let re = Regex::new(r"^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}$").unwrap();
    if re.is_match(&val) {
        Ok(())
    } else {
        Err(String::from(
            "the range needs to be of the format x.x.x.x/y",
        ))
    }
}

fn validate_output(val: std::string::String) -> Result<(), String> {
    if !val.is_empty() {
        if val.ne("json") && val.ne("table") {
            return Err(String::from(
                "The only allowed formats are \"json\" and \"table\"",
            ));
        }
    }

    Ok(())
}
