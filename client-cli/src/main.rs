use clap::{Command, Arg};
use zeroize::Zeroizing;
use std::error::Error;
use rustyline::{Editor, error::ReadlineError};
use rpassword::prompt_password_stdout;

use client_core::{init, Profile, Server, TaskRequest};

pub fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    //tracing_subscriber::fmt().with_thread_names(true).with_max_level(tracing::Level::INFO).init();

    let tx = init("./serv")?;

    let mut rl = Editor::<()>::new();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                let mut command = String::from("session ");
                command.push_str(line.as_str());
                rl.add_history_entry(line.as_str());
                let args = match Command::new("Session")
                    .help_expected(true)
                    .subcommand(Command::new("list")
                                .about("List sessions")
                                )
                     .subcommand(Command::new("open")
                                .about("Open session.")
                                .arg(Arg::new("name")
                                    .required(true)
                                    .takes_value(true)
                                    .help("Session name"))
                                    )
                    .subcommand(Command::new("new")
                                .about("Create new session.")
                                .arg(Arg::new("name")
                                    .required(true)
                                    .takes_value(true)
                                    .help("Session name"))
                                ).try_get_matches_from(command.as_str().split(" ")) {
                    Ok(v) => v,
                    Err(e) => {
                        e.print().ok();
                        continue
                    }
                };

                if let Some(_) = args.subcommand_matches("list") {
                    println!(
                        "{0: <10} | {1: <10}",
                        "id", "name"
                    );
                    let mut count = 0;
                    for session in Profile::get_profiles(&tx)? {
                        println!(
                            "{0: <10} | {1: <10}",
                            count, session
                        );
                        count += 1;
                    }
                } else if let Some(sub_args) = args.subcommand_matches("new") {
                    let name: String = sub_args.value_of_t("name")?;
                    let pass         = Zeroizing::new(prompt_password_stdout("Password: ")?);

                    match Profile::add_profile(&tx, &name, pass) {
                        Ok(_) => {
                            session(&name, &tx)?;
                        },
                        Err(e) => println!("Error: {}", e)
                    }
                } else if let Some(sub_args) = args.subcommand_matches("open") {
                    let name: String  = sub_args.value_of_t("name")?;
                    let pass         = Zeroizing::new(prompt_password_stdout("Password: ")?);

                    match Profile::change_profile(&tx, Some((name.clone(), pass))) {
                        Ok(_) => {
                            session(&name, &tx)?;
                        },
                        Err(e) => println!("Error: {}", e)
                    }
                }
            },
            Err(ReadlineError::Interrupted |  ReadlineError::Eof) => {
                return Ok(());
            },
            Err(err) => {
                println!("Error reading line: {}", err);
                return Ok(());
            }
        }
    }
}

pub fn session(name: &str, tx: &TaskRequest) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut rl = Editor::<()>::new();
    loop {
        let readline = rl.readline(&format!("{} >> ", name));
        match readline {
            Ok(line) => {
                let mut command = String::from("session ");
                command.push_str(line.as_str());
                rl.add_history_entry(line.as_str());
                let args = match Command::new("Session")
                    .help_expected(true)
                    .subcommand(Command::new("server")
                                .about("Server commands.")
                                .subcommand(Command::new("add")
                                            .about("Add new server")
                                            .arg(Arg::new("insecure")
                                                .short('i')
                                                .long("insecure")
                                                .help("Allow invalid certificat"))
                                            .arg(Arg::new("host")
                                                .required(true)
                                                .takes_value(true)
                                                .help("Server name (domain or port)"))
                                            .arg(Arg::new("port")
                                                .required(true)
                                                .takes_value(true)
                                                .help("Server port"))
                                            )
                                .subcommand(Command::new("activity")
                                            .about("Show servers activity")
                                            )
                                ).try_get_matches_from(command.as_str().split(" ")) {
                    Ok(v) => v,
                    Err(e) => {
                        e.print().ok();
                        continue
                    }
                };

                if let Some(sub_args) = args.subcommand_matches("server") {
                    if let Some(_) = sub_args.subcommand_matches("activity") {
                        let current_time = chrono::offset::Utc::now().timestamp();
                        println!(
                            "{0: <20} | {1: <10}",
                            "server", "status"
                        );
                        for (server, last_seen) in Server::get_activity(&tx)? {
                            println!(
                                "{0: <20} | {1: <30}",
                                server,
                                if last_seen == 0 {
                                    "inactive".to_owned()
                                } else {
                                    if current_time - last_seen < 20 {
                                        "active".to_owned()
                                    } else {
                                        format!("last seen {}", chrono_humanize::HumanTime::from(chrono::Duration::seconds(current_time - last_seen)))
                                    }
                                }
                            );
                        }
                    } else if let Some(args) = sub_args.subcommand_matches("add") {
                        let host: String  = args.value_of_t("host").unwrap();
                        let port: u16     = match args.value_of_t("port") {
                            Ok(v) => v,
                            Err(e) => {
                                println!("{}", e);
                                continue;
                            }
                        };
                        let allow_insecure: bool  = args.is_present("insecure");

                        match Server::add(tx, &host, port, allow_insecure) {
                            Ok(v) => println!("{:?}", v),
                            Err(e) => println!("{}", e)
                        }
                    }
                }
            },
            Err(ReadlineError::Interrupted |  ReadlineError::Eof) => {
                Profile::change_profile(&tx, None).ok();
                return Ok(());
            },
            Err(err) => {
                println!("Error reading line: {}", err);
                return Ok(());
            }
        }
    }
}
