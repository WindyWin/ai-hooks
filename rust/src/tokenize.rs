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

const LITERAL_SPECIALS: &str = ";()&|<>";

fn protect(c: char) -> Option<char> {
    LITERAL_SPECIALS
        .chars()
        .position(|x| x == c)
        .and_then(|i| char::from_u32(0xE000 + i as u32))
}

fn unprotect(c: char) -> Option<char> {
    let i = (c as u32).checked_sub(0xE000)? as usize;
    LITERAL_SPECIALS.chars().nth(i)
}

/// Swap the shell punctuation that bash takes literally (`\;`, `\(`, `';'`, "a;b") for private characters, so the
/// tokenizer does not mistake `find -exec ... \;` or `\( -name a \)` for a separator. Only the characters change:
/// the quotes and every other backslash stay for the lexer.
fn protect_literals(cmd: &str) -> String {
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = String::with_capacity(cmd.len());
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                    out.push(c);
                } else if c == '\\' && q == '"' && i + 1 < chars.len() {
                    out.push(c);
                    out.push(protect(chars[i + 1]).unwrap_or(chars[i + 1]));
                    i += 1;
                } else {
                    out.push(protect(c).unwrap_or(c));
                }
            }
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                out.push(c);
            }
            None if c == '\\' && i + 1 < chars.len() => {
                match protect(chars[i + 1]) {
                    Some(p) => out.push(p),
                    None => {
                        out.push(c);
                        out.push(chars[i + 1]);
                    }
                }
                i += 1;
            }
            None => out.push(c),
        }
        i += 1;
    }
    out
}

/// Back to the original characters. A token that is nothing but literal punctuation keeps a backslash (`\;`) so it
/// is not taken for a separator any more.
fn unprotect_token(tok: &str) -> String {
    if !tok.chars().any(|c| unprotect(c).is_some()) {
        return tok.to_string();
    }
    let text: String = tok.chars().map(|c| unprotect(c).unwrap_or(c)).collect();
    if tok.chars().all(|c| unprotect(c).is_some()) {
        format!("\\{text}")
    } else {
        text
    }
}

/// Split a shell command into tokens; falls back to whitespace splitting on malformed quoting.
pub fn tokenize(cmd: &str) -> Vec<String> {
    let cmd = cmd.replace('\n', " ; ");
    match shlex_split(&protect_literals(&cmd)) {
        Ok(tokens) => tokens.iter().map(|t| unprotect_token(t)).collect(),
        Err(_) => cmd
            .split(py_is_space)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
    }
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
    fn escaped_and_quoted_punctuation_is_a_word_not_a_separator() {
        assert_eq!(
            t(r"find . -exec cat {} \; -print"),
            ["find", ".", "-exec", "cat", "{}", r"\;", "-print"]
        );
        assert_eq!(
            t(r"find . \( -name a \) -exec cat {} +"),
            ["find", ".", r"\(", "-name", "a", r"\)", "-exec", "cat", "{}", "+"]
        );
        assert_eq!(t("a ';' b \";\""), ["a", r"\;", "b", r"\;"]);
        assert_eq!(t("echo 'a;b' x\\;y"), ["echo", "a;b", "x;y"]);
        assert_eq!(t("echo \"a\\;b\""), ["echo", r"a\;b"]);
        assert_eq!(t("a \\\\; b"), ["a", "\\", ";", "b"]);
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
