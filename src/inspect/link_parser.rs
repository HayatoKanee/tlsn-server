/// Parsed parameters from a CS2 inspect link.
#[derive(Debug, Clone)]
pub struct InspectParams {
    pub s: Option<u64>, // Steam ID (inventory items)
    pub m: Option<u64>, // Market listing ID (market items)
    pub a: u64,         // Asset ID (always present)
    pub d: u64,         // D parameter (always present)
}

/// Parse a CS2 inspect link into its S/M/A/D parameters.
///
/// Supports formats:
///   steam://rungame/730/.../+csgo_econ_action_preview S{steamId}A{assetId}D{d}
///   steam://rungame/730/.../+csgo_econ_action_preview M{marketId}A{assetId}D{d}
///   URL-encoded variants (%20 instead of space)
pub fn parse_inspect_link(url: &str) -> Option<InspectParams> {
    let decoded = url.replace("%20", " ");

    let params_str = decoded
        .split("csgo_econ_action_preview")
        .nth(1)?
        .trim();

    let mut s = None;
    let mut m = None;
    let mut a = None;
    let mut d = None;

    let mut chars = params_str.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            'S' | 's' => {
                chars.next();
                s = parse_number(&mut chars);
            }
            'M' | 'm' => {
                chars.next();
                m = parse_number(&mut chars);
            }
            'A' | 'a' => {
                chars.next();
                a = parse_number(&mut chars);
            }
            'D' | 'd' => {
                chars.next();
                d = parse_number(&mut chars);
            }
            _ => {
                chars.next();
            }
        }
    }

    Some(InspectParams {
        s,
        m,
        a: a?,
        d: d?,
    })
}

fn parse_number(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u64> {
    let mut num = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            num.push(c);
            chars.next();
        } else {
            break;
        }
    }
    if num.is_empty() {
        None
    } else {
        num.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inventory_link() {
        let link = "steam://rungame/730/76561202255233023/+csgo_econ_action_preview S76561198084749846A698323590D7935523998312483177";
        let params = parse_inspect_link(link).unwrap();
        assert_eq!(params.s, Some(76561198084749846));
        assert_eq!(params.a, 698323590);
        assert_eq!(params.d, 7935523998312483177);
        assert!(params.m.is_none());
    }

    #[test]
    fn parse_market_link() {
        let link = "steam://rungame/730/76561202255233023/+csgo_econ_action_preview M625254122282020305A6760346663D30614827701953021";
        let params = parse_inspect_link(link).unwrap();
        assert_eq!(params.m, Some(625254122282020305));
        assert_eq!(params.a, 6760346663);
        assert_eq!(params.d, 30614827701953021);
        assert!(params.s.is_none());
    }

    #[test]
    fn parse_url_encoded_link() {
        let link = "steam://rungame/730/76561202255233023/+csgo_econ_action_preview%20S76561198084749846A698323590D7935523998312483177";
        let params = parse_inspect_link(link).unwrap();
        assert_eq!(params.s, Some(76561198084749846));
        assert_eq!(params.a, 698323590);
        assert_eq!(params.d, 7935523998312483177);
    }

    #[test]
    fn invalid_link_no_preview() {
        assert!(parse_inspect_link("https://example.com").is_none());
    }

    #[test]
    fn invalid_link_missing_a() {
        let link = "steam://rungame/730/76561202255233023/+csgo_econ_action_preview S76561198084749846D7935523998312483177";
        assert!(parse_inspect_link(link).is_none());
    }

    #[test]
    fn invalid_link_missing_d() {
        let link = "steam://rungame/730/76561202255233023/+csgo_econ_action_preview S76561198084749846A698323590";
        assert!(parse_inspect_link(link).is_none());
    }
}
