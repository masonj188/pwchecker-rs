//! pwchecker_rs
//!
//! pwchecker_rs allows you to conveniently query the [haveibeenpwned.com](https://haveibeenpwned.com)
//! api so you can check whether or not a password has been involved in a data breach.
//!
//! # Examples
//! ```
//! let res = pwchecker_rs::check_for_pwnage("helloworld");
//!
//! assert!(res.unwrap().times_pwned > 0);
//! ```

use std::error::Error;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use reqwest::blocking;

const API_URL: &str = "https://api.pwnedpasswords.com/range/";

/// Passwd contains two fields, the password checked for pwnage and the number of times
/// that password has been pwned.
#[derive(Debug)]
pub struct Passwd {
    pub text: String,
    pub times_pwned: i32,
}

/// Checks given password for a breach according to haveibeenpwned.com.
///
/// # Examples
/// ```
/// let res = pwchecker_rs::check_for_pwnage("helloworld");
///
/// assert!(res.unwrap().times_pwned > 0);
pub fn check_for_pwnage(pass: &str) -> Result<Passwd, Box<dyn Error>> {
    if pass.len() <= 0 {
        return Err("Password can't be length 0")?;
    }

    let hash = get_hash(pass);

    let res = blocking::get(format!("{}{}", API_URL, &hash[..5]))?.text()?;

    for line in res.lines() {
        let values = line.split(':').collect::<Vec<&str>>();
        let (hash_suffix, num) = (values[0], values[1]);

        if format!("{}{}", &hash[..5], hash_suffix).eq(&hash) {
            return Ok(Passwd {
                text: pass.to_string(),
                times_pwned: num.parse()?,
            });
        }
    }

    Ok(Passwd {
        text: pass.to_string(),
        times_pwned: 0,
    })
}

fn get_hash(pass: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.input_str(pass);

    hasher.result_str().to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[should_panic]
    fn test_zero_len() {
        check_for_pwnage("").unwrap();
    }

    #[test]
    fn check_hello_world() {
        assert!(check_for_pwnage("helloworld").unwrap().times_pwned > 0);
    }
}
