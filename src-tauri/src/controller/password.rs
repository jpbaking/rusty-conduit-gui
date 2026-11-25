//! The strength rule for a new master password or backup password.
//!
//! It applies when a password is chosen: creating the vault, changing the master password, and
//! exporting a backup with secrets. Unlocking and importing take the password as it was set.
//! There is no maximum: Argon2id accepts any length the app can send.

use super::{AppError, SecretInput};

/// Fewest characters (Unicode scalar values, not bytes) a new password may have.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// The rules `password` does not meet, as phrases that complete "needs …".
pub fn password_problems(password: &str) -> Vec<&'static str> {
    let mut problems = Vec::new();
    if password.chars().count() < MIN_PASSWORD_CHARS {
        problems.push("at least 8 characters");
    }
    if !password.chars().any(char::is_uppercase) {
        problems.push("an uppercase letter");
    }
    if !password.chars().any(char::is_lowercase) {
        problems.push("a lowercase letter");
    }
    if !password.chars().any(char::is_numeric) {
        problems.push("a number");
    }
    if !password.chars().any(is_special) {
        problems.push("a special character");
    }
    problems
}

/// Punctuation, symbols, and spaces: anything that is not a letter or a digit.
fn is_special(c: char) -> bool {
    !c.is_alphanumeric()
}

/// Refuses a new `what` password that does not meet the rule, naming every missing part.
pub(crate) fn check_new_password(password: &SecretInput, what: &str) -> Result<(), AppError> {
    let problems = password_problems(password.as_str());
    if problems.is_empty() {
        return Ok(());
    }
    Err(AppError::Invalid(format!("the {what} needs {}", join(&problems))))
}

fn join(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_needs_length_and_every_kind_of_character() {
        assert!(password_problems("Str0ng!pw").is_empty());
        assert!(password_problems("Ünï cødé 9").is_empty(), "Unicode letters and a space count");
        assert_eq!(password_problems("Ab1!xyz"), ["at least 8 characters"]);
        assert_eq!(password_problems("abcdefg1!"), ["an uppercase letter"]);
        assert_eq!(password_problems("ABCDEFG1!"), ["a lowercase letter"]);
        assert_eq!(password_problems("Abcdefgh!"), ["a number"]);
        assert_eq!(password_problems("Abcdefgh1"), ["a special character"]);
        assert_eq!(password_problems("").len(), 5);
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // Eight characters, more than eight bytes.
        assert!(password_problems("Éé1!éééé").is_empty());
    }

    #[test]
    fn the_error_names_every_missing_part() {
        let error = check_new_password(&SecretInput::new("abc"), "backup password").unwrap_err();
        assert_eq!(
            error.to_string(),
            "the backup password needs at least 8 characters, an uppercase \
             letter, a number, and a special character"
        );
    }
}
