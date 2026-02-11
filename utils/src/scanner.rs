//! Text scanning with the `Scanner` type.

type Result<T> = std::result::Result<T, ScannerError>;

#[inline(always)]
pub fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t')
}

#[inline(always)]
pub fn is_newline(c: u8) -> bool {
    matches!(c, b'\r' | b'\n')
}

#[inline(always)]
pub fn is_not_newline(c: u8) -> bool {
    !is_newline(c)
}

#[inline(always)]
pub fn not_comma_or_newline(c: u8) -> bool {
    !is_newline(c) && c != b','
}

#[inline(always)]
pub fn is_alphabetic(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

#[inline(always)]
pub fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// A text scanner for sequentially reading bytes from an input slice.
///
/// The `Scanner` provides methods to iterate over the input while
/// tracking the current position in terms of line and column numbers.
pub struct Scanner<'buf> {
    /// The input byte slice being scanned.
    buffer: &'buf [u8],
    /// The current position in the input.
    position: Position,
    /// The current byte index within the buffer.
    index: usize,
    /// The total length of the input buffer.
    len: usize,
}

impl<'buf> Scanner<'buf> {
    /// Create a `Scanner` from a byte slice.
    pub const fn new(buffer: &'buf [u8]) -> Self {
        Scanner {
            buffer,
            len: buffer.len(),
            position: Position::new(),
            index: 0usize,
        }
    }

    /// Returns a slice of the remaining bytes in the scanner.
    #[inline]
    pub fn remaining(&self) -> &[u8] {
        self.as_ref()
    }

    /// Advances the scanner by `n` bytes.
    ///
    /// Stops early if the end of the buffer is reached.
    pub fn advance_by(&mut self, n: usize) {
        for _ in 0..n {
            if self.next_byte().is_none() {
                break;
            }
        }
    }

    /// Reads the next byte and advance the scanner position.
    ///
    /// If the scanner has reached the end of the buffer, it returns `None`.
    pub fn next_byte(&mut self) -> Option<u8> {
        self.peek_byte().copied().map(|c| {
            self.bump(c);
            return c;
        })
    }

    pub fn next(&mut self) -> Result<u8> {
        self.next_byte().ok_or(ScannerError::Eof)
    }

    pub fn is_eof(&self) -> bool {
        self.index == self.len
    }

    /// Returns a reference to the next byte without advancing the scanner
    /// position.
    ///
    /// If the scanner has reached the end of the buffer, it returns `None`.
    #[inline(always)]
    pub fn peek_byte(&self) -> Option<&u8> {
        self.buffer.get(self.index)
    }

    /// Get a reference to the current scanner [`Position`].
    #[inline]
    pub fn position(&self) -> &Position {
        &self.position
    }

    /// Returns `true` if the upcoming bytes match the given `prefix`.
    #[inline]
    pub fn matches_prefix(&self, prefix: &[u8]) -> bool {
        self.remaining().starts_with(prefix)
    }

    /// Get `n` bytes without advance.
    ///
    /// Returns `None` if there are fewer than `n` bytes remaining.
    #[inline(always)]
    pub fn peek_bytes(&self, n: usize) -> Option<&[u8]> {
        self.remaining().get(..n)
    }

    fn read_number_str(&mut self) -> &'buf str {
        let bytes = self.read_while(|b| b.is_ascii_digit() || b == b'.');
        // SAFETY: `bytes` contains only ASCII digits (0–9) and optionally '.',
        // all of which are valid single-byte UTF-8 characters.
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }

    /// Reads a `u32` number until a non-digit is found.
    ///
    /// Returns an error if no valid digits were found or if the number is out
    /// of range.
    pub fn read_u32(&mut self) -> Result<u32> {
        self.read_number_str()
            .parse()
            .or_else(|_| Err(ScannerError::InvalidNumber))
    }

    /// Read a `u16` number until an invalid digit is found.
    ///
    /// Returns an error if no valid digits were found or if the number is out
    /// of range.
    pub fn read_u16(&mut self) -> Result<u16> {
        self.read_number_str()
            .parse()
            .or_else(|_| Err(ScannerError::InvalidNumber))
    }

    /// Read a `u64` number until an invalid digit is found.
    ///
    /// Returns an error if no valid digits were found or if the number is out
    /// of range.
    pub fn read_u64(&mut self) -> Result<u64> {
        self.read_number_str()
            .parse()
            .or_else(|_| Err(ScannerError::InvalidNumber))
    }

    /// Read a `i64` number until an invalid digit is found.
    ///
    /// Returns an error if no valid digits were found or if the number is out
    /// of range.
    pub fn read_i64(&mut self) -> Result<i64> {
        self.read_number_str()
            .parse()
            .or_else(|_| Err(ScannerError::InvalidNumber))
    }

    /// Read a `f32` number until an invalid digit is found.
    ///
    /// Returns an error if no valid digits were found or if the number is out
    /// of range.
    pub fn read_f32(&mut self) -> Result<f32> {
        self.read_number_str()
            .parse()
            .or_else(|_| Err(ScannerError::InvalidNumber))
    }

    /// Call the `predicate` closure for each element in the buffer and next_byte
    /// the scanner while the closure returns `true`.
    #[inline(always)]
    pub fn read_while(&mut self, predicate: impl Fn(u8) -> bool) -> &'buf [u8] {
        let start = self.index;
        while let Some(&c) = self.peek_byte() {
            if predicate(c) {
                self.bump(c);
            } else {
                break;
            }
        }
        let end = self.index;
        // SAFETY: We ensure `start..end` is valid because we only next_byted indexes
        // within the buffer bounds.
        unsafe { self.buffer.get_unchecked(start..end) }
    }

    /// peek_byte bytes in the buffer while the `predicate` returns true.
    ///
    /// Does not next_byte the scanner position.
    pub fn peek_while(&'buf self, predicate: impl Fn(u8) -> bool) -> &'buf [u8] {
        let buffer = self.remaining();

        let n = buffer
            .iter()
            .position(|&b| !predicate(b))
            .unwrap_or(buffer.len());

        // SAFETY: `n` is guaranteed to be ≤ `buffer.len()`, so the range is always
        // in-bounds.
        unsafe { buffer.get_unchecked(..n) }
    }

    /// Peek next byte if `condition` returns `true`.
    pub fn peek_if(&self, condition: impl Fn(u8) -> bool) -> Option<u8> {
        self.peek_byte().filter(|&&byte| condition(byte)).copied()
    }

    /// Read next bytes if equals to `expected`
    pub fn must_read_bytes(&mut self, expected: &[u8]) -> Result<()> {
        let remaining = &self.buffer[self.index..];
        let iter = remaining.iter().zip(expected);
        for (&found, &expected) in iter {
            if found != expected {
                return Err(ScannerError::UnexpectedByte { expected, found });
            }
            self.bump(found);
        }
        Ok(())
    }

    /// Read next byte if equals to `expected`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the next byte is not equal to `expected` or
    /// the end of the slice has been reached.
    pub fn must_read(&mut self, expected: u8) -> Result<()> {
        match self.peek_byte().copied() {
            Some(found) if expected == found => {
                self.bump(found);
                Ok(())
            }
            Some(found) => Err(ScannerError::UnexpectedByte { expected, found }),
            None => Err(ScannerError::Eof),
        }
    }

    /// Reads bytes until the next byte equals `byte`.
    ///
    /// The matching byte is not consumed.
    #[inline]
    pub fn read_until(&mut self, byte: u8) -> &'buf [u8] {
        self.read_while(|b| b != byte)
    }

    #[inline]
    pub fn read_until_as_str(&mut self, byte: u8) -> Result<&'buf str> {
        self.read_while_as_str(|b| b != byte)
    }

    /// Reads bytes while `predicate` returns true and converts them to a string
    /// slice.
    ///
    /// # Errors
    ///
    /// Returns `ScannerError::InvalidUtf8` if the resulting bytes are not
    /// valid UTF-8.
    pub fn read_while_as_str(&mut self, predicate: impl Fn(u8) -> bool) -> Result<&'buf str> {
        let bytes = self.read_while(predicate);

        std::str::from_utf8(bytes).or_else(|_| Err(ScannerError::InvalidUtf8))
    }

    /// Same as [`Scanner::read_while`] but returns the bytes as a string slice
    /// without checking UTF-8.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `predicate` only returns `true` for bytes that form valid
    /// UTF-8.
    #[inline]
    pub unsafe fn read_while_as_str_unchecked(
        &mut self,
        predicate: impl Fn(u8) -> bool,
    ) -> &'buf str {
        let bytes = self.read_while(predicate);

        // SAFETY: The caller guarantees that `predicate` only matches bytes forming valid
        // UTF-8.
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }

    /// Call the `predicate` closure for next byte and read it if
    /// the closure returns `true`.
    ///
    /// # Returns
    ///
    /// The byte readed.
    #[inline(always)]
    pub fn next_byte_if(&mut self, predicate: impl FnOnce(u8) -> bool) -> Option<u8> {
        match self.peek_byte() {
            Some(&matched) if predicate(matched) => {
                self.bump(matched);

                Some(matched)
            }
            _ => None,
        }
    }

    /// Consume and return the next byte if it is equal to `expected`.
    pub fn advance_if_eq(&mut self, expected: u8) -> Option<u8> {
        self.next_byte_if(|b| b == expected)
    }

    #[inline(always)]
    fn bump(&mut self, byte: u8) {
        self.index += 1;
        if byte == b'\n' {
            self.position.column = 1;
            self.position.line += 1;
        } else {
            self.position.column += 1;
        }
    }
}

impl AsRef<[u8]> for Scanner<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        // SAFETY: `self.index..self.len` is guaranteed to be within the bounds of
        // `self.buffer`.
        unsafe { self.buffer.get_unchecked(self.index..self.len) }
    }
}

impl ToString for Scanner<'_> {
    fn to_string(&self) -> String {
        String::from_utf8_lossy(self.remaining()).into()
    }
}

/// Errors that can occur while reading the buffer.
#[derive(Debug, PartialEq, Clone, Copy, Eq)]
pub enum ScannerError {
    /// End of the buffer reached unexpectedly.
    Eof,

    /// The byte read did not match the expected value.
    UnexpectedByte {
        /// The byte that was expected.
        expected: u8,
        /// The byte that was actually found.
        found: u8,
    },

    /// A number could not be parsed from the input.
    InvalidNumber,

    /// The bytes are not valid UTF-8.
    InvalidUtf8,
}

/// Represents a position within the scanned input.
///
/// Both `line` and `column` are 1-based:
/// - `line = 1` means the first line of the input.
/// - `column = 1` means the first byte of the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// Current line number (starting from 1).
    pub line: usize,
    /// Current column number (starting from 0).
    pub column: usize,
}

impl Position {
    /// Create a new `Position` starting at line 1, column 0.
    pub const fn new() -> Self {
        Self { line: 1, column: 0 }
    }
}

impl Default for Position {
    fn default() -> Self {
        Self { line: 1, column: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_must_read_expected_byte_succeeds() {
        let mut scanner = Scanner::new(b"Hello, World!");
        let result = scanner.must_read(b'H');
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_must_read_fails_on_eof() {
        let mut scanner = Scanner::new(b"");
        let err = scanner.must_read(b'h').unwrap_err();
        assert_eq!(err, ScannerError::Eof);
    }

    #[test]
    fn test_read_while_digits_should_return_only_digits() {
        let mut scanner = Scanner::new(b"123hello");
        let digits = scanner.read_while(|b| b.is_ascii_digit());
        assert_eq!(digits, b"123");
    }

    #[test]
    fn read_while_as_str_should_return_only_alphabetic() {
        let mut scanner = Scanner::new(b"hello123");
        let string = scanner.read_while_as_str(|b| b.is_ascii_alphabetic());
        assert_eq!(string, Ok("hello"));
    }

    #[test]
    fn read_while_as_str_fails_on_invalid_utf8() {
        let mut scanner = Scanner::new(&[0xff, 0xff]);
        let err = scanner.read_while_as_str(|_| true).unwrap_err();
        assert_eq!(err, ScannerError::InvalidUtf8);
    }

    #[test]
    fn test_peek_while_should_return_only_alphabetic() {
        let scanner = Scanner::new(b"hello123");
        let letters = scanner.peek_while(|b| b.is_ascii_alphabetic());
        assert_eq!(letters, b"hello");
        assert_eq!(scanner.remaining(), b"hello123");
    }

    #[test]
    fn test_read_u32_valid_number_returns_value() {
        let mut scanner = Scanner::new(b"12345hello");
        let result = scanner.read_u32();
        assert_eq!(result, Ok(12345u32));
    }

    #[test]
    fn test_read_u32_invalid_number_returns_error() {
        let mut scanner = Scanner::new(b"hello");
        let err = scanner.read_u32().unwrap_err();
        assert_eq!(err, ScannerError::InvalidNumber);
    }

    #[test]
    fn test_read_u16_valid_number_returns_value() {
        let mut scanner = Scanner::new(b"65535xyz");
        let result = scanner.read_u16();
        assert_eq!(result, Ok(65535u16));
    }

    #[test]
    fn test_read_f32_valid_number_returns_value() {
        let mut scanner = Scanner::new(b"3.1415hello");
        let result = scanner.read_f32();
        assert_eq!(result, Ok(3.1415f32));
    }

    #[test]
    fn test_read_f32_invalid_number_returns_error() {
        let mut scanner = Scanner::new(b"hello");
        let err = scanner.read_f32().unwrap_err();
        assert_eq!(err, ScannerError::InvalidNumber);
    }
}
