//! A table of 45 hostile XML inputs and the redirect scenarios of a fake-server suite.

use super::*;

const GOOD: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<clientConfig version=\"1.1\"><emailProvider id=\"x.test\">",
    "<domain>x.test</domain><incomingServer type=\"imap\"><hostname>imap.%EMAILDOMAIN%</hostname><port>993</port>",
    "<socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication>",
    "</incomingServer><outgoingServer type=\"smtp\"><hostname>smtp.x.test</hostname><port>465</port><socketType>SSL</socketType>",
    "<username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication></outgoingServer></emailProvider></clientConfig>\n"
);

fn body() -> &'static str {
    GOOD.split_once("?>\n").unwrap().1
}

fn utf16le(s: &str, bom: bool) -> Vec<u8> {
    let mut v = if bom { vec![0xff, 0xfe] } else { vec![] };
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn lol() -> Vec<u8> {
    let mut ents = String::from("<!ENTITY lol \"lol\">");
    for i in 1..10 {
        let r = if i > 1 {
            format!("&lol{};", i - 1)
        } else {
            "&lol;".into()
        };
        ents.push_str(&format!("<!ENTITY lol{i} \"{}\">", r.repeat(10)));
    }
    format!(
        "<?xml version=\"1.0\"?><!DOCTYPE clientConfig [{ents}]><clientConfig>&lol9;</clientConfig>"
    )
    .into_bytes()
}

fn cases() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let b = |s: &str| s.as_bytes().to_vec();
    let g = |from: &str, to: &str| GOOD.replace(from, to).into_bytes();
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(GOOD.as_bytes());
    let attrs: Vec<String> = (0..9).map(|i| format!("a{i}=\"1\"")).collect();
    let mut total = format!("<r><t>{}</t>", "x".repeat(2000));
    for _ in 0..20 {
        total.push_str(&format!("<t>{}</t>", "x".repeat(2000)));
    }
    total.push_str("</r>");
    let oversize = format!(
        "{}<!--{}--></clientConfig>",
        &GOOD[..GOOD.len() - "</clientConfig>\n".len()],
        "x".repeat(1 << 20)
    );
    let mut at_limit = b"<a>".to_vec();
    at_limit.extend(std::iter::repeat_n(b'x', 65536 - 7 + 1));
    at_limit.extend_from_slice(b"</a>");
    vec![
        ("valid_minimal", b(GOOD), "ok"),
        ("valid_bom", bom, "ok"),
        ("valid_no_decl", b(body()), "ok"),
        (
            "valid_cdata_comment",
            g(
                "<domain>x.test</domain>",
                "<!-- c --><domain><![CDATA[x.test]]></domain>",
            ),
            "ok",
        ),
        (
            "valid_numeric_refs",
            g("x.test</domain>", "&#120;&#x2e;test</domain>"),
            "ok",
        ),
        ("billion_laughs", lol(), "doctype"),
        (
            "xxe_system_entity",
            b(
                "<?xml version=\"1.0\"?><!DOCTYPE c [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><clientConfig>&xxe;</clientConfig>",
            ),
            "doctype",
        ),
        (
            "xxe_parameter_entity",
            b("<!DOCTYPE c [<!ENTITY % p SYSTEM \"http://evil.test/x.dtd\"> %p;]><clientConfig/>"),
            "doctype",
        ),
        (
            "doctype_public",
            b(
                "<!DOCTYPE clientConfig PUBLIC \"-//X//DTD X//EN\" \"http://evil.test/x.dtd\"><clientConfig/>",
            ),
            "doctype",
        ),
        (
            "doctype_inside_root",
            b("<clientConfig><!DOCTYPE x></clientConfig>"),
            "doctype",
        ),
        (
            "undeclared_entity",
            b("<clientConfig>&xxe;</clientConfig>"),
            "bad_entity",
        ),
        (
            "entity_nul_ref",
            b("<clientConfig>&#0;</clientConfig>"),
            "bad_entity",
        ),
        (
            "entity_surrogate_ref",
            b("<clientConfig>&#xD800;</clientConfig>"),
            "bad_entity",
        ),
        (
            "entity_huge_ref",
            b("<clientConfig>&#99999999999;</clientConfig>"),
            "bad_entity",
        ),
        (
            "xinclude_ignored",
            g(
                "<domain>",
                "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"file:///etc/passwd\"/><domain>",
            ),
            "ok",
        ),
        (
            "pi_stylesheet",
            b(
                "<?xml version=\"1.0\"?><?xml-stylesheet href=\"http://evil.test/x.xsl\"?><clientConfig/>",
            ),
            "processing_instruction",
        ),
        (
            "pi_in_body",
            b("<clientConfig><?php echo 1; ?></clientConfig>"),
            "processing_instruction",
        ),
        (
            "utf16_bom",
            utf16le(
                &GOOD.replace("encoding=\"UTF-8\"", "encoding=\"UTF-16\""),
                true,
            ),
            "not_utf8",
        ),
        ("utf16_no_bom", utf16le(body(), false), "bad_name"),
        ("latin1_decl", g("UTF-8", "ISO-8859-1"), "encoding"),
        (
            "invalid_utf8",
            b"<clientConfig>\xff\xfe</clientConfig>".to_vec(),
            "not_utf8",
        ),
        (
            "nul_byte",
            b"<clientConfig>a\x00b</clientConfig>".to_vec(),
            "bad_char",
        ),
        (
            "control_char",
            b"<clientConfig>a\x07b</clientConfig>".to_vec(),
            "bad_char",
        ),
        ("oversize_1mib", oversize.into_bytes(), "too_large"),
        ("size_at_limit_plus_1", at_limit, "too_large"),
        (
            "deep_nesting_100",
            format!("{}{}", "<a>".repeat(100), "</a>".repeat(100)).into_bytes(),
            "depth",
        ),
        (
            "deep_nesting_100k",
            "<a>".repeat(20000).into_bytes(),
            "depth",
        ),
        (
            "too_many_elements",
            format!("<r>{}</r>", "<a/>".repeat(1100)).into_bytes(),
            "too_many_elements",
        ),
        (
            "too_many_attrs",
            format!("<r {}/>", attrs.join(" ")).into_bytes(),
            "too_many_attrs",
        ),
        (
            "duplicate_attr",
            b("<r a=\"1\" a=\"2\"/>"),
            "duplicate_attr",
        ),
        (
            "long_name",
            format!("<{}/>", "a".repeat(65)).into_bytes(),
            "name_too_long",
        ),
        (
            "long_attr",
            format!("<r a=\"{}\"/>", "x".repeat(600)).into_bytes(),
            "attr_too_long",
        ),
        (
            "long_text",
            format!("<r>{}</r>", "x".repeat(3000)).into_bytes(),
            "text_too_long",
        ),
        ("total_text", total.into_bytes(), "total_text_too_long"),
        (
            "entity_text_growth",
            format!("<r>{}</r>", "&amp;".repeat(2100)).into_bytes(),
            "text_too_long",
        ),
        ("mismatched_tags", b("<a><b></a></b>"), "mismatched_end_tag"),
        ("two_roots", b("<a/><b/>"), "trailing_content"),
        ("text_after_root", b("<a/>junk"), "trailing_content"),
        ("unterminated", b("<clientConfig><a>"), "eof"),
        ("empty", vec![], "no_root"),
        ("lt_in_attr", b("<r a=\"<\"/>"), "unexpected"),
        (
            "double_dash_comment",
            b("<r><!-- a -- b --></r>"),
            "unexpected",
        ),
        ("cdata_end_in_text", b("<r>a]]>b</r>"), "unexpected"),
        ("non_ascii_name", b("<rü/>"), "unexpected"),
        (
            "xml_decl_not_first",
            b(" <?xml version=\"1.0\"?><r/>"),
            "processing_instruction",
        ),
    ]
}

#[test]
fn hostile_table() {
    let cs = cases();
    assert_eq!(cs.len(), 45);
    for (name, data, want) in cs {
        let got = match xml::parse(&data, Limits::AUTOCONFIG) {
            Ok(_) => "ok",
            Err(e) => e.code(),
        };
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn maps_good_config() {
    let c = parse(GOOD.as_bytes(), "x.test").unwrap();
    assert!(c.is_usable());
    assert_eq!(c.imap[0].host, "imap.x.test");
    assert_eq!((c.imap[0].port, c.imap[0].sock), (993, Sock::Ssl));
    assert_eq!(c.smtp[0].username.as_deref(), Some("%EMAILADDRESS%"));
    assert!(!c.imap[0].oauth2);
}

#[test]
fn drops_disallowed_ports_and_bad_entries() {
    let doc = GOOD
        .replace("<port>993</port>", "<port>1993</port>")
        .replace("smtp.x.test", "10.0.0.5")
        .replace("type=\"imap\"", "type=\"pop3\"");
    let c = parse(doc.as_bytes(), "x.test").unwrap();
    assert!(!c.is_usable());
    assert_eq!(c.dropped, vec!["incoming_pop3", "bad_host"]);
    let c = parse(
        GOOD.replace("<port>993</port>", "<port>1993</port>")
            .as_bytes(),
        "x.test",
    )
    .unwrap();
    assert_eq!(c.dropped, vec!["port_not_allowed"]);
    assert!(matches!(
        parse(b"<html/>", "x.test"),
        Err(ParseError::Schema("root_not_clientConfig"))
    ));
    assert_eq!(
        parse(b"<!DOCTYPE html><html/>", "x.test")
            .unwrap_err()
            .to_string(),
        "xml:doctype"
    );
}

#[test]
fn hosts_are_ldh() {
    for (h, ok) in [
        ("imap.x.test", true),
        ("x", false),
        ("1.2.3.4", false),
        ("IMAP.x.test", false),
        ("a..b", false),
        ("-a.b", false),
        ("a.b.", false),
        (&"a.".repeat(127), false),
    ] {
        assert_eq!(valid_host(h), ok, "{h}");
    }
}

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

#[test]
fn approved_url_policy() {
    for (u, ok) in [
        ("https://autoconfig.x.test/mail/config-v1.1.xml", true),
        (
            "https://x.test/.well-known/autoconfig/mail/config-v1.1.xml#f",
            true,
        ),
        ("http://autoconfig.x.test/mail/config-v1.1.xml", false),
        ("https://autoconfig.x.test:8443/mail/config-v1.1.xml", false),
        ("https://u:p@autoconfig.x.test/", false),
        ("https://10.0.0.5/", false),
        ("https://[::1]/", false),
        ("https://localhost/", false),
    ] {
        let mut x = url(u);
        assert_eq!(check_url(&mut x).is_ok(), ok, "{u}");
        if ok {
            assert!(x.fragment().is_none());
        }
    }
}

#[test]
fn redirect_rules() {
    let start = url("https://autoconfig.x.test/mail/config-v1.1.xml");
    // 3 hops accepted, the 4th refused before it is requested.
    let mut u = start.clone();
    for hop in 0..3 {
        u = next_hop(&u, &format!("/r{hop}"), hop).unwrap();
    }
    assert_eq!(next_hop(&u, "/r3", 3), Err("too_many_redirects"));
    // https -> http refused.
    assert_eq!(
        next_hop(&start, "http://x.test/c.xml", 0),
        Err("redirect_https_to_http")
    );
    // Explicit port refused.
    assert_eq!(
        next_hop(&start, "https://x.test:8443/c.xml", 0),
        Err("explicit port not allowed")
    );
    // IP literal refused; private names are refused by the caller's address policy.
    assert_eq!(
        next_hop(&start, "https://10.0.0.5/c.xml", 0),
        Err("IP literal not allowed")
    );
    // A cross-domain redirect is followed; the caller asks the user to confirm it.
    assert_eq!(
        next_hop(&start, "https://autoconfig.hoster.test/c.xml", 0)
            .unwrap()
            .host_str(),
        Some("autoconfig.hoster.test")
    );
    assert_eq!(
        next_hop(&start, "javascript:alert(1)", 0),
        Err("https only")
    );
}
