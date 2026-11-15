//! The reader process: confined, then answering requests about the image on
//! descriptor 3 from descriptor 0, on descriptor 1.

use std::io::{BufWriter, Write};
use std::os::fd::FromRawFd as _;

use crate::image::Image;
use crate::protocol::{DataFrames, Request, Tag, read_frame, write_frame};

/// Where the reader finds the image.
pub(crate) const IMAGE_FD: i32 = 3;

/// Runs a reader with `args`, the arguments after the subcommand, and exits.
pub fn serve(args: &[String]) -> ! {
    let code = match run(args) {
        Ok(()) => 0,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "disk reader: {err}");
            1
        }
    };
    std::process::exit(code)
}

fn run(args: &[String]) -> std::io::Result<()> {
    let limits = crate::Limits::from_args(args)?;
    confine(&limits)?;
    // SAFETY: the parent hands these descriptors over open, and nothing
    // else in this process owns them.
    let (image, input, output) = unsafe {
        (
            std::fs::File::from_raw_fd(IMAGE_FD),
            std::fs::File::from_raw_fd(0),
            std::fs::File::from_raw_fd(1),
        )
    };
    let image = Image::open(image);
    answer(image, input, output)
}

#[cfg(target_os = "linux")]
fn confine(limits: &crate::Limits) -> std::io::Result<()> {
    crate::confine::confine(limits)
}

#[cfg(not(target_os = "linux"))]
fn confine(_: &crate::Limits) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "a disk reader confines itself with Linux facilities, and runs only on Linux",
    ))
}

/// Answers every request on `input` until it closes. An image that does not
/// load is not fatal: every request is answered with why.
pub(crate) fn answer(
    image: Result<Image, String>,
    mut input: impl std::io::Read,
    output: impl Write,
) -> std::io::Result<()> {
    let mut output = BufWriter::with_capacity(64 << 10, output);
    while let Some((tag, payload)) = read_frame(&mut input)? {
        if tag != Tag::Request {
            return Err(std::io::Error::other("expected a request"));
        }
        let request: Request = serde_json::from_slice(&payload)?;
        let image = match &image {
            Ok(image) => image,
            Err(err) => {
                write_frame(&mut output, Tag::Error, err.as_bytes())?;
                output.flush()?;
                continue;
            }
        };
        let answered = match request {
            Request::ListDir { path } => image.list(&path).and_then(|entries| {
                reply(&mut output, Tag::Reply, &entries).map_err(|err| err.to_string())
            }),
            Request::Stat { path } => image.stat(&path).and_then(|stat| {
                reply(&mut output, Tag::Reply, &stat).map_err(|err| err.to_string())
            }),
            Request::Read { path, offset, len } => read(image, &path, offset, len, &mut output),
            Request::Tar {
                path,
                max_bytes,
                max_entries,
            } => tar(image, &path, max_bytes, max_entries, &mut output),
        };
        if let Err(err) = answered {
            write_frame(&mut output, Tag::Error, err.as_bytes())?;
        }
        output.flush()?;
    }
    Ok(())
}

fn read(
    image: &Image,
    path: &str,
    offset: u64,
    len: u64,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut frames = DataFrames::new(&mut *output);
    image.read(path, offset, len, |bytes| frames.write_all(bytes))?;
    frames.into_inner().map_err(|err| err.to_string())?;
    write_frame(output, Tag::End, &[]).map_err(|err| err.to_string())
}

fn tar(
    image: &Image,
    path: &str,
    max_bytes: u64,
    max_entries: u64,
    output: &mut impl Write,
) -> Result<(), String> {
    let mut frames = DataFrames::new(&mut *output);
    let summary = image.tar(path, max_bytes, max_entries, &mut frames)?;
    frames.into_inner().map_err(|err| err.to_string())?;
    reply(output, Tag::End, &summary).map_err(|err| err.to_string())
}

fn reply(out: &mut impl Write, tag: Tag, value: &impl serde::Serialize) -> std::io::Result<()> {
    write_frame(out, tag, &serde_json::to_vec(value)?)
}
