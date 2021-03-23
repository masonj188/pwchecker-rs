# pwchecker-rs

pwchecker-rs exports a single function `check_for_pwnage` that takes a string a returns results from [haveibeenpwned.com](https://haveibeenpwned.com).

The returned value is a `Result<Passwd, Error>`, the `Passwd` struct has the public fields `text` which contains the password, and `times_pwned` which contains the number of times the password has been pwned.