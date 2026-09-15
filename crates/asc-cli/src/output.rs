//! Output commitment (interfaces.md §6): one serialization, an atomic file
//! replacement, then stdout.
//!
//! Commit order: the payload is fully rendered and validated first; `-o`
//! goes through a same-directory hidden temporary file (write, flush,
//! `sync_all`, rename) so an existing regular file is replaced atomically and
//! a failure preserves it; stdout is written last, after the commit point —
//! a stdout failure never rolls the file back. Symlinks, directories, the
//! input file itself and hardlinks of the input are refused. A closed stdout
//! pipe is a quiet success (`BrokenPipe`); on Unix the default `SIGPIPE`
//! disposition terminates first anyway.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// What happened after the payload was committed.
pub(crate) enum WriteOutcome {
    /// Everything written; the command exits 0.
    Committed,
    /// stdout's consumer closed the pipe; a quiet exit 0, no error text.
    BrokenPipe,
}

/// An output-layer failure: a stable code prefix plus human context.
/// Both codes exit 1 — they are output errors, not query errors.
pub(crate) struct OutputError {
    code: &'static str,
    context: String,
}

impl OutputError {
    fn refused(context: impl Into<String>) -> Self {
        Self { code: "OutputRefused", context: context.into() }
    }

    fn io(context: impl Into<String>, source: &io::Error) -> Self {
        Self { code: "OutputIo", context: format!("{}: {source}", context.into()) }
    }
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.context)
    }
}

/// Commits the payload to `-o` (atomic replacement) and then stdout.
pub(crate) fn commit(
    payload: &str,
    output: Option<&Path>,
    input: &Path,
) -> Result<WriteOutcome, OutputError> {
    if let Some(path) = output {
        replace_file(path, payload.as_bytes(), input)?;
    }
    write_stdout(payload.as_bytes())
}

fn write_stdout(payload: &[u8]) -> Result<WriteOutcome, OutputError> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let result = lock.write_all(payload).and_then(|()| lock.flush());
    match result {
        Ok(()) => Ok(WriteOutcome::Committed),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(WriteOutcome::BrokenPipe),
        Err(error) => Err(OutputError::io("write stdout", &error)),
    }
}

/// Replaces `path` with `payload` atomically: refuses symlink/directory/
/// same-as-input targets, writes a hidden same-directory temporary file,
/// flushes and syncs it, then renames it over the destination. Any failure
/// preserves the existing file and removes the temporary.
fn replace_file(path: &Path, payload: &[u8], input: &Path) -> Result<(), OutputError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(OutputError::refused(format!(
                "{} is a symbolic link; refusing to replace it",
                path.display()
            )));
        }
        if metadata.is_dir() {
            return Err(OutputError::refused(format!(
                "{} is a directory",
                path.display()
            )));
        }
    }
    if aliases_input(path, input).map_err(|error| OutputError::io("stat output", &error))? {
        return Err(OutputError::refused(format!(
            "{} is the input file (or a hardlink of it); refusing to overwrite it",
            path.display()
        )));
    }

    let temporary = temporary_path(path)?;
    let write = OpenOptions::new().write(true).create_new(true).open(&temporary);
    let mut file = match write {
        Ok(file) => file,
        Err(error) => {
            return Err(OutputError::io(
                format!("create temporary file {}", temporary.display()),
                &error,
            ));
        }
    };
    let written =
        file.write_all(payload).and_then(|()| file.flush()).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(OutputError::io(format!("write {}", path.display()), &error));
    }

    let renamed = rename_over(&temporary, path);
    if let Err(error) = renamed {
        let _ = fs::remove_file(&temporary);
        return Err(OutputError::io(format!("replace {}", path.display()), &error));
    }
    Ok(())
}

/// Unix `rename` replaces an existing destination atomically. Platforms
/// without that guarantee (Windows) remove the destination first — the
/// replacement window is a documented DIST-03 item.
fn rename_over(temporary: &Path, path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(temporary, path)
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(temporary, path)
    }
}

/// Hidden same-directory name with a random-ish suffix; the `create_new`
/// open makes collisions harmless (a new suffix is chosen instead).
fn temporary_path(path: &Path) -> Result<PathBuf, OutputError> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().map_or_else(|| "output".to_owned(), |name| {
        name.to_string_lossy().into_owned()
    });
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or_default();
    loop {
        let candidate = directory.join(format!(
            ".{name}.rasc-{}-{nanos:x}-{}.tmp",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
}

/// True when `path` and `input` denote the same file: same device and inode
/// on Unix (which also catches hardlinks), canonical paths elsewhere.
fn aliases_input(path: &Path, input: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (fs::metadata(path), fs::metadata(input)) {
            (Ok(output), Ok(source)) => {
                Ok(output.dev() == source.dev() && output.ino() == source.ino())
            }
            (Err(error), _) | (_, Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(false)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        match (fs::canonicalize(path), fs::canonicalize(input)) {
            (Ok(output), Ok(source)) => Ok(output == source),
            (Err(error), _) | (_, Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(false)
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
}
