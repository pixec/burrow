//! Turning an exec's argv into what `CreateProcessW` takes.
//!
//! Windows passes a program one string, not an argv: each program splits it
//! again, almost always by the rules of `CommandLineToArgvW` and the C
//! runtime. [`quote`] is the inverse of those rules, so a program that splits
//! its command line the usual way gets back exactly the argv the caller sent.
//!
//! Two cases do not split that way and are mapped explicitly:
//!
//! - `sh -c SCRIPT` (or `bash`, `/bin/sh`, `/bin/bash`, with `-c` or `-lc`),
//!   which is how every SDK sends a shell command. With a POSIX shell on the
//!   guest (see [`posix_shell`] on Windows), that shell runs the argv as sent.
//!   Without one, the script goes to `cmd.exe /d /s /c "SCRIPT"`: cmd.exe is on
//!   every Windows image and understands the `&&`, `||`, `|` and redirections
//!   SDK one-liners are made of, which PowerShell 5.1 does not. Positional
//!   arguments after the script have no cmd.exe equivalent and are refused
//!   rather than dropped.
//! - A `.bat` or `.cmd` program, which only cmd.exe can run and which splits
//!   its arguments by cmd.exe's rules, not the C runtime's. It is run as
//!   `cmd.exe /d /s /c "..."`, with each argument quoted for cmd.exe, and an
//!   argument cmd.exe would still expand (`"`, `%`, a line break) is refused:
//!   there is no quoting that makes those literal to a batch file.

/// What to launch: the image `CreateProcessW` loads and the command line it
/// hands that image.
#[derive(Debug, PartialEq, Eq)]
pub struct Launch {
    pub application: String,
    pub command_line: String,
    /// Set when a POSIX `sh -c` was mapped onto cmd.exe, for the log.
    pub is_shell_mapped: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LaunchError {
    Empty,
    NotFound(String),
    /// Something that cannot be expressed to cmd.exe: why.
    Unrepresentable(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::Empty => write!(f, "cmd must not be empty"),
            LaunchError::NotFound(program) => write!(f, "program not found: {program}"),
            LaunchError::Unrepresentable(why) => write!(f, "{why}"),
        }
    }
}

/// Quotes one argument so `CommandLineToArgvW` gives it back unchanged.
///
/// Backslashes are literal except before a quote, where each must be doubled
/// and the quote itself escaped; the argument's own closing quote counts, so
/// trailing backslashes are doubled too.
pub fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// An argv as one command line, each argument [`quote`]d.
///
/// The program name is the exception: Windows reads it up to the next space,
/// or between quotes with no escaping at all, so it is only ever wrapped.
pub fn join(argv: &[String]) -> String {
    let mut parts = Vec::with_capacity(argv.len());
    if let Some(program) = argv.first() {
        parts.push(if program.contains([' ', '\t']) || program.is_empty() {
            format!("\"{program}\"")
        } else {
            program.clone()
        });
    }
    parts.extend(argv.iter().skip(1).map(|arg| quote(arg)));
    parts.join(" ")
}

/// Quotes one argument for cmd.exe running a batch file, or says why it
/// cannot be.
fn quote_for_cmd(arg: &str) -> Result<String, LaunchError> {
    if arg.contains(['"', '%', '\r', '\n']) {
        return Err(LaunchError::Unrepresentable(format!(
            "argument {arg:?} cannot be passed to a batch file: cmd.exe expands '\"', '%' and line breaks whatever the quoting"
        )));
    }
    if arg.is_empty()
        || arg.contains([
            ' ', '\t', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', '!',
        ])
    {
        Ok(format!("\"{arg}\""))
    } else {
        Ok(arg.to_string())
    }
}

/// The POSIX shells an SDK names, and the flags that make the next argument a
/// script.
fn shell_script(argv: &[String]) -> Option<usize> {
    let is_shell = matches!(
        argv.first().map(String::as_str),
        Some("sh" | "bash" | "/bin/sh" | "/bin/bash" | "/usr/bin/sh" | "/usr/bin/bash")
    );
    let is_script = matches!(argv.get(1).map(String::as_str), Some("-c" | "-lc"));
    (is_shell && is_script && argv.len() >= 3).then_some(2)
}

fn is_batch(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".bat") || lower.ends_with(".cmd")
}

/// Works out what to launch for `argv`.
///
/// `cmd_exe` is the full path of cmd.exe, `posix_shell` the guest's POSIX sh
/// if it has one, and `resolve` finds a program the way [`resolve_program`]
/// does.
pub fn plan(
    argv: &[String],
    cmd_exe: &str,
    posix_shell: Option<&str>,
    resolve: impl Fn(&str) -> Option<String>,
) -> Result<Launch, LaunchError> {
    if argv.is_empty() {
        return Err(LaunchError::Empty);
    }
    if let Some(script) = shell_script(argv) {
        if let Some(shell) = posix_shell {
            let mut mapped = argv.to_vec();
            mapped[0] = shell.to_string();
            return Ok(Launch {
                application: shell.to_string(),
                command_line: join(&mapped),
                is_shell_mapped: false,
            });
        }
        if argv.len() > script + 1 {
            return Err(LaunchError::Unrepresentable(
                "sh -c with positional arguments needs a POSIX shell on the guest; cmd.exe has no $0 or $1".into(),
            ));
        }
        // `/s` makes cmd.exe strip exactly the outer quotes and run what is
        // between them as written, so the script needs no escaping of its own.
        return Ok(Launch {
            application: cmd_exe.to_string(),
            command_line: format!("\"{cmd_exe}\" /d /s /c \"{}\"", argv[script]),
            is_shell_mapped: true,
        });
    }
    let application = resolve(&argv[0]).ok_or_else(|| LaunchError::NotFound(argv[0].clone()))?;
    if is_batch(&application) {
        let mut line = format!("\"{application}\"");
        for arg in &argv[1..] {
            line.push(' ');
            line.push_str(&quote_for_cmd(arg)?);
        }
        return Ok(Launch {
            application: cmd_exe.to_string(),
            command_line: format!("\"{cmd_exe}\" /d /s /c \"{line}\""),
            is_shell_mapped: false,
        });
    }
    let mut mapped = argv.to_vec();
    mapped[0].clone_from(&application);
    Ok(Launch {
        command_line: join(&mapped),
        application,
        is_shell_mapped: false,
    })
}

/// Finds `program` the way a Windows shell would: a name with a directory in
/// it is mapped as a path and tried as is and with each `PATHEXT` extension;
/// a bare name is looked for in each `PATH` directory the same way.
///
/// `CreateProcessW` alone only ever appends `.exe`, which misses `npm.cmd`
/// and every other script shim a toolchain installs.
pub fn resolve_program(
    program: &str,
    path_var: &str,
    pathext: &str,
    system_drive: char,
    exists: impl Fn(&str) -> bool,
) -> Option<String> {
    let extensions: Vec<&str> = pathext
        .split(';')
        .filter(|ext| ext.starts_with('.'))
        .collect();
    let has_extension = std::path::Path::new(program).extension().is_some();
    let candidates = |base: &str| {
        let mut out = Vec::new();
        if has_extension {
            out.push(base.to_string());
        }
        out.extend(extensions.iter().map(|ext| format!("{base}{ext}")));
        out
    };
    if program.contains(['\\', '/', ':']) {
        let mapped = crate::paths::windows::to_windows(program, system_drive).ok()?;
        return candidates(&mapped).into_iter().find(|path| exists(path));
    }
    path_var
        .split(';')
        .filter(|dir| !dir.is_empty())
        .flat_map(|dir| {
            candidates(&crate::paths::windows::join(
                dir.trim_end_matches('\\'),
                program,
            ))
        })
        .find(|path| exists(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CommandLineToArgvW`'s rules for the arguments after the program, as
    /// the C runtime applies them, to check [`quote`] against.
    fn split(line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            if i == chars.len() {
                break;
            }
            let mut arg = String::new();
            let mut quoted = false;
            while i < chars.len() && (quoted || (chars[i] != ' ' && chars[i] != '\t')) {
                let mut backslashes = 0;
                while i < chars.len() && chars[i] == '\\' {
                    backslashes += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    arg.extend(std::iter::repeat_n('\\', backslashes / 2));
                    if backslashes % 2 == 1 {
                        arg.push('"');
                    } else if quoted && i + 1 < chars.len() && chars[i + 1] == '"' {
                        arg.push('"');
                        i += 1;
                    } else {
                        quoted = !quoted;
                    }
                    i += 1;
                } else {
                    arg.extend(std::iter::repeat_n('\\', backslashes));
                    if i < chars.len() && (quoted || (chars[i] != ' ' && chars[i] != '\t')) {
                        arg.push(chars[i]);
                        i += 1;
                    }
                }
            }
            args.push(arg);
        }
        args
    }

    #[test]
    fn quoting_round_trips_through_the_runtime_rules() {
        let args = [
            "plain",
            "",
            "two words",
            "tab\there",
            "quote\"inside",
            "trailing\\",
            "trailing space\\",
            "C:\\Program Files\\x\\",
            "\\\\server\\share",
            "back\\\\\"slash",
            "\"",
            "\\\"",
            "ünïcode ✓",
        ];
        for arg in args {
            let line = format!("prog {}", quote(arg));
            assert_eq!(split(&line)[1..], [arg.to_string()], "{arg:?} as {line:?}");
        }
        let argv: Vec<String> = std::iter::once("C:\\a b\\prog.exe")
            .chain(args)
            .map(String::from)
            .collect();
        let line = join(&argv);
        assert!(line.starts_with("\"C:\\a b\\prog.exe\" "));
        let rest = &line["\"C:\\a b\\prog.exe\" ".len()..];
        assert_eq!(split(&format!("p {rest}"))[1..], argv[1..]);
    }

    #[test]
    fn plain_arguments_are_left_alone() {
        assert_eq!(quote("--flag=value"), "--flag=value");
        assert_eq!(quote("C:\\x\\y"), "C:\\x\\y");
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote("a\\ b\\"), "\"a\\ b\\\\\"");
    }

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    const CMD: &str = "C:\\Windows\\System32\\cmd.exe";

    fn found(program: &str) -> Option<String> {
        Some(match program {
            "npm" => "C:\\node\\npm.cmd".into(),
            other => format!("C:\\bin\\{other}.exe"),
        })
    }

    #[test]
    fn a_shell_command_goes_to_cmd_without_a_posix_shell() {
        let launch = plan(
            &argv(&["/bin/sh", "-c", "echo hi && dir"]),
            CMD,
            None,
            found,
        )
        .unwrap();
        assert_eq!(launch.application, CMD);
        assert_eq!(
            launch.command_line,
            format!("\"{CMD}\" /d /s /c \"echo hi && dir\"")
        );
        assert!(launch.is_shell_mapped);
        let launch = plan(&argv(&["bash", "-lc", "x"]), CMD, None, found).unwrap();
        assert!(launch.command_line.ends_with("/c \"x\""));
    }

    #[test]
    fn a_shell_command_keeps_its_argv_with_a_posix_shell() {
        let sh = "C:\\Program Files\\Git\\bin\\sh.exe";
        let launch = plan(
            &argv(&["/bin/sh", "-c", "echo $0 $1", "a", "b c"]),
            CMD,
            Some(sh),
            found,
        )
        .unwrap();
        assert_eq!(launch.application, sh);
        assert_eq!(
            launch.command_line,
            format!("\"{sh}\" -c \"echo $0 $1\" a \"b c\"")
        );
        assert!(!launch.is_shell_mapped);
    }

    #[test]
    fn positional_arguments_cmd_cannot_take_are_refused() {
        let err = plan(&argv(&["sh", "-c", "echo $1", "x", "y"]), CMD, None, found).unwrap_err();
        assert!(matches!(err, LaunchError::Unrepresentable(_)));
    }

    #[test]
    fn a_program_runs_by_its_resolved_path() {
        let launch = plan(&argv(&["python", "-c", "print(1)"]), CMD, None, found).unwrap();
        assert_eq!(launch.application, "C:\\bin\\python.exe");
        assert_eq!(launch.command_line, "C:\\bin\\python.exe -c print(1)");
        // `sh` without `-c` is just a program.
        let launch = plan(&argv(&["sh", "script.sh"]), CMD, None, found).unwrap();
        assert_eq!(launch.application, "C:\\bin\\sh.exe");
    }

    #[test]
    fn a_batch_file_runs_under_cmd_with_its_arguments_quoted_for_cmd() {
        let launch = plan(
            &argv(&["npm", "install", "left-pad@^1.0", "a&b"]),
            CMD,
            None,
            found,
        )
        .unwrap();
        assert_eq!(launch.application, CMD);
        assert_eq!(
            launch.command_line,
            format!(
                "\"{CMD}\" /d /s /c \"\"C:\\node\\npm.cmd\" install \"left-pad@^1.0\" \"a&b\"\""
            )
        );
        let err = plan(&argv(&["npm", "run", "%PATH%"]), CMD, None, found).unwrap_err();
        assert!(matches!(err, LaunchError::Unrepresentable(_)));
    }

    #[test]
    fn an_unknown_program_is_not_found() {
        let err = plan(&argv(&["nope"]), CMD, None, |_| None).unwrap_err();
        assert_eq!(err, LaunchError::NotFound("nope".into()));
        assert_eq!(plan(&[], CMD, None, found).unwrap_err(), LaunchError::Empty);
    }

    #[test]
    fn programs_resolve_through_path_and_pathext() {
        let files = [
            "C:\\node\\npm.cmd",
            "C:\\py\\python.exe",
            "C:\\work\\run.exe",
        ];
        let exists = |path: &str| files.iter().any(|file| file.eq_ignore_ascii_case(path));
        let path = "C:\\py;C:\\node\\";
        let ext = ".COM;.EXE;.BAT;.CMD";
        assert_eq!(
            resolve_program("npm", path, ext, 'C', exists).as_deref(),
            Some("C:\\node\\npm.CMD")
        );
        assert_eq!(
            resolve_program("python", path, ext, 'C', exists).as_deref(),
            Some("C:\\py\\python.EXE")
        );
        assert_eq!(
            resolve_program("python.exe", path, ext, 'C', exists).as_deref(),
            Some("C:\\py\\python.exe")
        );
        assert_eq!(
            resolve_program("/work/run", path, ext, 'C', exists).as_deref(),
            Some("C:\\work\\run.EXE")
        );
        assert_eq!(resolve_program("missing", path, ext, 'C', exists), None);
    }
}
