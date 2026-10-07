//! HTML entity encode/decode.

const NAMED: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", '\u{00A0}'),
    ("copy", '©'),
    ("reg", '®'),
    ("trade", '™'),
    ("hellip", '…'),
    ("mdash", '—'),
    ("ndash", '–'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("ldquo", '“'),
    ("rdquo", '”'),
];

pub fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                out.push_str(&format!("&#{};", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '&' {
            // Find terminating ';' within a reasonable window.
            if let Some(end) = (i + 1..(i + 12).min(bytes.len())).find(|&j| bytes[j] == ';') {
                let entity: String = bytes[i + 1..end].iter().collect();
                if let Some(c) = resolve_entity(&entity) {
                    out.push(c);
                    i = end + 1;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn resolve_entity(entity: &str) -> Option<char> {
    if let Some(stripped) = entity.strip_prefix('#') {
        let code = if let Some(h) = stripped.strip_prefix('x').or_else(|| stripped.strip_prefix('X')) {
            u32::from_str_radix(h, 16).ok()?
        } else {
            stripped.parse::<u32>().ok()?
        };
        return char::from_u32(code);
    }
    for (name, ch) in NAMED {
        if *name == entity {
            return Some(*ch);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_roundtrip() {
        let s = "<script>alert('xss')</script>";
        let enc = html_encode(s);
        assert!(enc.contains("&lt;") && enc.contains("&gt;") && enc.contains("&#39;"));
        assert_eq!(html_decode(&enc), s);
    }

    #[test]
    fn numeric_entities() {
        assert_eq!(html_decode("&#60;&#62;"), "<>");
        assert_eq!(html_decode("&#x3C;"), "<");
    }

    #[test]
    fn named_entities() {
        assert_eq!(html_decode("&amp;&nbsp;&copy;"), "&\u{00A0}©");
    }

    #[test]
    fn passes_through_unknown() {
        assert_eq!(html_decode("&unknown;"), "&unknown;");
    }
}
