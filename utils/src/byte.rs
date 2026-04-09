#[must_use]
pub fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

#[must_use]
pub fn is_newline(b: u8) -> bool {
    matches!(b, b'\r' | b'\n')
}

#[must_use]
pub fn is_alphabetic(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

#[must_use]
pub fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}
