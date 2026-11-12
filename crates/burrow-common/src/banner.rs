const FIRST_YEAR: i32 = 2026;

/// Prints the startup banner to stderr.
pub fn print(version: &str) {
    let year = time::OffsetDateTime::now_utc().year();
    let years = if year > FIRST_YEAR {
        format!("{FIRST_YEAR} - {year}")
    } else {
        FIRST_YEAR.to_string()
    };
    eprintln!(
        "{}",
        include_str!("banner.txt")
            .replace("{version}", &version_line(version))
            .replace("{years}", &years)
    );
}

fn version_line(version: &str) -> String {
    match env!("BURROW_COMMIT") {
        "" => version.to_string(),
        commit => format!("{version} ({commit})"),
    }
}
