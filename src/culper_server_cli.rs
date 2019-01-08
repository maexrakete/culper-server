use clap::{App, Arg};

pub fn build() -> App<'static, 'static> {
    App::new("culper-server")
        .version("0.1.0")
        .about("Server side part of culper")
        .arg(
            Arg::with_name("home")
                .value_name("DIRECTORY")
                .long("home")
                .help("Sets the home directory to use")
                .required(false),
        )
}
