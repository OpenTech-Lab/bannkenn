pub const MAX_VEC_ITEMS: usize = 100;
pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_IP_INPUT_BYTES: usize = 64;

/// Truncate a Vec to at most `max` elements.
pub fn cap_vec<T>(mut v: Vec<T>, max: usize) -> Vec<T> {
    v.truncate(max);
    v
}

/// Truncate a String to at most `max_bytes` on a valid UTF-8 boundary.
pub fn cap_string(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let truncated = s.floor_char_boundary(max_bytes);
    s[..truncated].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_vec_within_limit() {
        let v = vec![1, 2, 3];
        assert_eq!(cap_vec(v, 5), vec![1, 2, 3]);
    }

    #[test]
    fn cap_vec_at_limit() {
        let v = vec![1, 2, 3];
        assert_eq!(cap_vec(v, 3), vec![1, 2, 3]);
    }

    #[test]
    fn cap_vec_over_limit() {
        let v = vec![1, 2, 3, 4, 5];
        assert_eq!(cap_vec(v, 3), vec![1, 2, 3]);
    }

    #[test]
    fn cap_vec_empty() {
        let v: Vec<i32> = vec![];
        assert_eq!(cap_vec(v, 5), Vec::<i32>::new());
    }

    #[test]
    fn cap_string_within_limit() {
        let s = "hello".to_string();
        assert_eq!(cap_string(s, 10), "hello");
    }

    #[test]
    fn cap_string_at_limit() {
        let s = "hello".to_string();
        assert_eq!(cap_string(s, 5), "hello");
    }

    #[test]
    fn cap_string_over_limit() {
        let s = "hello world".to_string();
        assert_eq!(cap_string(s, 5), "hello");
    }

    #[test]
    fn cap_string_utf8_boundary() {
        // Multi-byte character at boundary
        let s = "abc\u{00E9}def".to_string(); // 'é' is 2 bytes
                                              // "abc" = 3 bytes, "é" = 2 bytes (bytes 3-4), "def" = 3 bytes
        let result = cap_string(s, 4);
        // Should truncate to "abc" since 'é' starts at byte 3 and ends at byte 5
        assert_eq!(result, "abc");
    }

    #[test]
    fn cap_string_utf8_cjk() {
        // CJK characters are 3 bytes each
        let s = "\u{3042}\u{3044}\u{3046}".to_string(); // "あいう"
        let result = cap_string(s, 4);
        // Only first character fits within 4 bytes (3 bytes)
        assert_eq!(result, "\u{3042}");
    }

    #[test]
    fn cap_string_empty() {
        assert_eq!(cap_string(String::new(), 10), "");
    }
}
