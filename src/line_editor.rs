use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, RawFd};

const HISTORY_LIMIT: usize = 100;
const LINE_LIMIT: usize = 64 * 1024;
const PROMPT: &str = "larp> ";

pub enum ReadLine {
    Line(String),
    End,
    Interrupted,
    TimedOut,
}

pub struct Editor {
    fd: RawFd,
    output_fd: RawFd,
    original: libc::termios,
    history: Vec<String>,
}

impl Editor {
    pub fn new(fd: RawFd, output_fd: RawFd) -> Result<Self, String> {
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err("could not read admin terminal settings".into());
        }
        Ok(Self {
            fd,
            output_fd,
            original,
            history: Vec::new(),
        })
    }

    pub fn read_line(&mut self, idle_ms: i32) -> Result<ReadLine, String> {
        let mut raw = self.original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &raw) } != 0 {
            return Err("could not enable admin line editing".into());
        }
        let _guard = RawGuard {
            fd: self.fd,
            original: self.original,
        };
        let mut line = Line::default();
        let mut draft = String::new();
        let mut position = None;
        let mut view_start = 0;
        let mut utf8 = Vec::with_capacity(4);
        let output_fd = unsafe { libc::dup(self.output_fd) };
        if output_fd < 0 {
            return Err("could not open admin terminal output".into());
        }
        let mut output = unsafe { File::from_raw_fd(output_fd) };
        write!(output, "\r\n{}", crate::ui::prompt())
            .map_err(|_| "could not write admin prompt")?;
        output.flush().map_err(|_| "could not flush admin prompt")?;
        loop {
            let Some(byte) = read_byte(self.fd, idle_ms)? else {
                output
                    .write_all(b"\r\n")
                    .map_err(|_| "could not write admin prompt")?;
                return Ok(ReadLine::TimedOut);
            };
            match byte {
                b'\r' | b'\n' => {
                    output
                        .write_all(b"\r\n")
                        .map_err(|_| "could not write admin prompt")?;
                    if !line.text.is_empty() && self.history.last() != Some(&line.text) {
                        self.history.push(line.text.clone());
                        if self.history.len() > HISTORY_LIMIT {
                            self.history.remove(0);
                        }
                    }
                    return Ok(ReadLine::Line(line.text));
                }
                3 => {
                    output
                        .write_all(b"^C\r\n")
                        .map_err(|_| "could not write admin prompt")?;
                    return Ok(ReadLine::Interrupted);
                }
                4 if line.text.is_empty() => {
                    output
                        .write_all(b"\r\n")
                        .map_err(|_| "could not write admin prompt")?;
                    return Ok(ReadLine::End);
                }
                1 => line.cursor = 0,
                5 => line.cursor = line.text.len(),
                2 => line.left(),
                6 => line.right(),
                8 | 127 => line.backspace(),
                21 => line.clear(),
                27 => match read_escape(self.fd)? {
                    Some(Key::Up) if !self.history.is_empty() => {
                        if position.is_none() {
                            draft = line.text.clone();
                            position = Some(self.history.len() - 1);
                        } else if let Some(index) = position.filter(|index| *index > 0) {
                            position = Some(index - 1);
                        }
                        line.replace(self.history[position.unwrap()].clone());
                    }
                    Some(Key::Down) => {
                        if let Some(index) = position {
                            if index + 1 < self.history.len() {
                                position = Some(index + 1);
                                line.replace(self.history[index + 1].clone());
                            } else {
                                position = None;
                                line.replace(draft.clone());
                            }
                        }
                    }
                    Some(Key::Right) => line.right(),
                    Some(Key::Left) => line.left(),
                    Some(Key::WordRight) => line.word_right(),
                    Some(Key::WordLeft) => line.word_left(),
                    Some(Key::Home) => line.cursor = 0,
                    Some(Key::End) => line.cursor = line.text.len(),
                    Some(Key::Delete) => line.delete(),
                    _ => {}
                },
                byte if byte >= 32 => {
                    utf8.push(byte);
                    match std::str::from_utf8(&utf8) {
                        Ok(value) => {
                            if line.text.len() + value.len() <= LINE_LIMIT {
                                line.insert(value);
                            }
                            utf8.clear();
                        }
                        Err(error) if error.error_len().is_none() && utf8.len() < 4 => {}
                        Err(_) => utf8.clear(),
                    }
                }
                _ => {}
            }
            redraw(
                &mut output,
                &line,
                &mut view_start,
                terminal_columns(self.output_fd),
            )?;
        }
    }
}

struct RawGuard {
    fd: RawFd,
    original: libc::termios,
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

fn read_byte(fd: RawFd, timeout_ms: i32) -> Result<Option<u8>, String> {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        if ready == 0 {
            return Ok(None);
        }
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("admin terminal poll failed".into());
        }
        let mut byte = 0u8;
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read == 1 {
            return Ok(Some(byte));
        }
        if read == 0 {
            return Err("admin terminal closed".into());
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err("could not read admin terminal".into());
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Left,
    Right,
    WordLeft,
    WordRight,
    Home,
    End,
    Delete,
}

fn parse_escape(sequence: &[u8]) -> Option<Key> {
    match sequence {
        b"b" | b"[1;3D" | b"[1;5D" => Some(Key::WordLeft),
        b"f" | b"[1;3C" | b"[1;5C" => Some(Key::WordRight),
        b"[A" | b"OA" => Some(Key::Up),
        b"[B" | b"OB" => Some(Key::Down),
        b"[C" | b"OC" => Some(Key::Right),
        b"[D" | b"OD" => Some(Key::Left),
        b"[H" | b"OH" | b"[1~" | b"[7~" => Some(Key::Home),
        b"[F" | b"OF" | b"[4~" | b"[8~" => Some(Key::End),
        b"[3~" => Some(Key::Delete),
        _ => None,
    }
}

fn read_escape(fd: RawFd) -> Result<Option<Key>, String> {
    let Some(prefix) = read_byte(fd, 50)? else {
        return Ok(None);
    };
    if prefix != b'[' && prefix != b'O' {
        return Ok(parse_escape(&[prefix]));
    }
    let mut sequence = vec![prefix];
    for _ in 0..12 {
        let Some(byte) = read_byte(fd, 50)? else {
            return Ok(None);
        };
        sequence.push(byte);
        if (b'@'..=b'~').contains(&byte) {
            return Ok(parse_escape(&sequence));
        }
    }
    Ok(None)
}

fn terminal_columns(fd: RawFd) -> usize {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0 && size.ws_col > 0 {
        usize::from(size.ws_col)
    } else {
        80
    }
}

fn redraw(
    output: &mut impl Write,
    line: &Line,
    view_start: &mut usize,
    columns: usize,
) -> Result<(), String> {
    // Leave the last column empty so the terminal never auto-wraps the prompt.
    let visible = columns.saturating_sub(PROMPT.len() + 1).max(1);
    let cursor = line.text[..line.cursor].chars().count();
    if cursor < *view_start {
        *view_start = cursor;
    } else if cursor >= *view_start + visible {
        *view_start = cursor - visible + 1;
    }
    let slice: String = line.text.chars().skip(*view_start).take(visible).collect();
    write!(
        output,
        "\r\x1b[2K{}{slice}\r\x1b[{}C",
        crate::ui::prompt(),
        PROMPT.len() + cursor - *view_start
    )
    .map_err(|_| "could not draw admin prompt")?;
    output
        .flush()
        .map_err(|_| "could not flush admin prompt".into())
}

#[derive(Default)]
struct Line {
    text: String,
    cursor: usize,
}

impl Line {
    fn replace(&mut self, text: String) {
        self.cursor = text.len();
        self.text = text;
    }
    fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }
    fn insert(&mut self, value: &str) {
        self.text.insert_str(self.cursor, value);
        self.cursor += value.len();
    }
    fn left(&mut self) {
        if let Some((index, _)) = self.text[..self.cursor].char_indices().next_back() {
            self.cursor = index;
        }
    }
    fn right(&mut self) {
        if let Some(character) = self.text[self.cursor..].chars().next() {
            self.cursor += character.len_utf8();
        }
    }
    fn word_left(&mut self) {
        while self.cursor > 0 {
            let character = self.text[..self.cursor].chars().next_back().unwrap();
            if character.is_alphanumeric() || character == '_' {
                break;
            }
            self.left();
        }
        while self.cursor > 0 {
            let character = self.text[..self.cursor].chars().next_back().unwrap();
            if !character.is_alphanumeric() && character != '_' {
                break;
            }
            self.left();
        }
    }
    fn word_right(&mut self) {
        while self.cursor < self.text.len() {
            let character = self.text[self.cursor..].chars().next().unwrap();
            if character.is_alphanumeric() || character == '_' {
                break;
            }
            self.right();
        }
        while self.cursor < self.text.len() {
            let character = self.text[self.cursor..].chars().next().unwrap();
            if !character.is_alphanumeric() && character != '_' {
                break;
            }
            self.right();
        }
    }
    fn backspace(&mut self) {
        let end = self.cursor;
        self.left();
        if self.cursor < end {
            self.text.drain(self.cursor..end);
        }
    }
    fn delete(&mut self) {
        if let Some(character) = self.text[self.cursor..].chars().next() {
            self.text
                .drain(self.cursor..self.cursor + character.len_utf8());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_escape, redraw, Editor, Key, Line, ReadLine};
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn editing_preserves_cursor_and_utf8_boundaries() {
        let mut line = Line::default();
        line.insert("ab");
        line.left();
        line.insert("é");
        assert_eq!(line.text, "aéb");
        line.backspace();
        assert_eq!(line.text, "ab");
        line.delete();
        assert_eq!(line.text, "a");
    }

    #[test]
    fn option_arrows_move_across_words_and_paths() {
        assert_eq!(parse_escape(b"[1;3D"), Some(Key::WordLeft));
        assert_eq!(parse_escape(b"[1;3C"), Some(Key::WordRight));
        assert_eq!(parse_escape(b"b"), Some(Key::WordLeft));
        assert_eq!(parse_escape(b"f"), Some(Key::WordRight));
        assert_eq!(parse_escape(b"[D"), Some(Key::Left));
        let mut line = Line::default();
        line.insert("secret import café/.env_op");
        line.word_left();
        assert_eq!(&line.text[line.cursor..], "env_op");
        line.word_left();
        assert_eq!(&line.text[line.cursor..], "café/.env_op");
        line.word_right();
        assert_eq!(&line.text[line.cursor..], "/.env_op");
    }

    #[test]
    fn long_input_stays_on_one_row_and_scrolls_with_cursor() {
        let mut line = Line::default();
        line.insert("command add project plan --cwd /a/very/long/path");
        let mut start = 0;
        let mut output = Vec::new();
        redraw(&mut output, &line, &mut start, 20).unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(start > 0);
        assert!(rendered.contains("larp> "));
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("long/path"));

        line.cursor = 0;
        output = Vec::new();
        redraw(&mut output, &line, &mut start, 20).unwrap();
        assert_eq!(start, 0);
        assert!(String::from_utf8(output).unwrap().contains("command add"));
    }

    #[test]
    fn up_and_down_arrows_navigate_history() {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut editor = Editor::new(slave, slave).unwrap();
            for _ in 0..3 {
                let line = editor.read_line(2000).unwrap();
                let ReadLine::Line(line) = line else {
                    panic!("expected input line")
                };
                sender.send(line).unwrap();
            }
            unsafe { libc::close(slave) };
        });
        thread::sleep(Duration::from_millis(30));
        master.write_all(b"first\n").unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            "first"
        );
        thread::sleep(Duration::from_millis(30));
        master.write_all(b"draft\x1b[A\n").unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            "first"
        );
        thread::sleep(Duration::from_millis(30));
        master.write_all(b"draft\x1b[A\x1b[B\n").unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            "draft"
        );
        worker.join().unwrap();
    }
}
