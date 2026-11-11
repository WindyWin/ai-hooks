//! Port of Python's `shlex.shlex(cmd, posix=True, punctuation_chars=True)` with
//! `whitespace_split = True` and comments disabled (bash only starts a comment at the start of a
//! word, and the hook must never skip text).

use crate::pathx::py_is_space;

const PUNCT: &str = "();<>|&";

#[derive(Clone, Copy, PartialEq)]
enum State {
    Space,
    Word,
    Punct,
    Quote(char),
    Escape,
    Done,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    pushback: Option<char>,
    state: State,
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

impl Lexer {
    fn next_char(&mut self) -> Option<char> {
        if let Some(c) = self.pushback.take() {
            return Some(c);
        }
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    /// `Ok(None)` is end of input; `Err` is an unterminated quote or trailing backslash.
    fn read_token(&mut self) -> Result<Option<String>, ()> {
        let mut token = String::new();
        let mut quoted = false;
        let mut escaped_state = State::Space;
        loop {
            let ch = self.next_char();
            match self.state {
                State::Done => {
                    token.clear();
                    break;
                }
                State::Space => match ch {
                    None => {
                        self.state = State::Done;
                        break;
                    }
                    Some(c) if is_ws(c) => {
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some('\\') => {
                        escaped_state = State::Word;
                        self.state = State::Escape;
                    }
                    Some(c) if PUNCT.contains(c) => {
                        token.push(c);
                        self.state = State::Punct;
                    }
                    Some(c @ ('\'' | '"')) => self.state = State::Quote(c),
                    Some(c) => {
                        token.push(c);
                        self.state = State::Word;
                    }
                },
                State::Quote(q) => {
                    quoted = true;
                    match ch {
                        None => return Err(()),
                        Some(c) if c == q => self.state = State::Word,
                        Some('\\') if q == '"' => {
                            escaped_state = State::Quote(q);
                            self.state = State::Escape;
                        }
                        Some(c) => token.push(c),
                    }
                }
                State::Escape => match ch {
                    None => return Err(()),
                    Some(c) => {
                        if let State::Quote(q) = escaped_state
                            && c != '\\'
                            && c != q
                        {
                            token.push('\\');
                        }
                        token.push(c);
                        self.state = escaped_state;
                    }
                },
                State::Word | State::Punct => match ch {
                    None => {
                        self.state = State::Done;
                        break;
                    }
                    Some(c) if is_ws(c) => {
                        self.state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if self.state == State::Punct => {
                        if PUNCT.contains(c) {
                            token.push(c);
                        } else {
                            self.pushback = Some(c);
                            self.state = State::Space;
                            break;
                        }
                    }
                    Some(c @ ('\'' | '"')) => self.state = State::Quote(c),
                    Some('\\') => {
                        escaped_state = State::Word;
                        self.state = State::Escape;
                    }
                    Some(c) if PUNCT.contains(c) => {
                        self.pushback = Some(c);
                        self.state = State::Space;
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) => token.push(c),
                },
            }
        }
        if !quoted && token.is_empty() {
            Ok(None)
        } else {
            Ok(Some(token))
        }
    }
}

fn shlex_split(cmd: &str) -> Result<Vec<String>, ()> {
    let mut lex = Lexer {
        chars: cmd.chars().collect(),
        pos: 0,
        pushback: None,
        state: State::Space,
    };
    let mut out = Vec::new();
    while let Some(tok) = lex.read_token()? {
        out.push(tok);
    }
    Ok(out)
}

/// Split a shell command into tokens; falls back to whitespace splitting on malformed quoting.
pub fn tokenize(cmd: &str) -> Vec<String> {
    let cmd = cmd.replace('\n', " ; ");
    shlex_split(&cmd).unwrap_or_else(|_| {
        cmd.split(py_is_space)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Vec<String> {
        tokenize(s)
    }

    #[test]
    fn words_quotes_and_escapes() {
        assert_eq!(t("cat 'a b' \"c d\" e\\ f"), ["cat", "a b", "c d", "e f"]);
        assert_eq!(t(r#"echo "a\"b" "c\d""#), ["echo", "a\"b", "c\\d"]);
        assert_eq!(t("echo ''"), ["echo", ""]);
    }

    #[test]
    fn punctuation_groups() {
        assert_eq!(
            t("a&&b||c|d;e"),
            ["a", "&&", "b", "||", "c", "|", "d", ";", "e"]
        );
        assert_eq!(
            t("cat<f >>o 2>&1"),
            ["cat", "<", "f", ">>", "o", "2", ">&", "1"]
        );
        assert_eq!(
            t("echo $(cat .env)"),
            ["echo", "$", "(", "cat", ".env", ")"]
        );
    }

    #[test]
    fn hash_is_not_a_comment() {
        assert_eq!(
            t("echo a#b && cat .env"),
            ["echo", "a#b", "&&", "cat", ".env"]
        );
        assert_eq!(
            t("echo x # hi\ncat .env"),
            ["echo", "x", "#", "hi", ";", "cat", ".env"]
        );
    }

    #[test]
    fn malformed_falls_back_to_whitespace_split() {
        assert_eq!(
            t("cat \"unterminated .env"),
            ["cat", "\"unterminated", ".env"]
        );
        assert_eq!(t("cat .env\\"), ["cat", ".env\\"]);
    }
}
