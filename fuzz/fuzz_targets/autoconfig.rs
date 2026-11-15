//! mailautodetect: the autoconfig parser and clientConfig mapper. Properties on every input:
//!  1. no panic, timeout or OOM;
//!  2. if parsing succeeds, depth, element count and every name/attribute bound hold;
//!  3. serialize(parse(x)) reparses (size limits relaxed for escaping growth) to the same tree;
//!  4. the clientConfig mapper only emits validated hosts and accepted ports.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mailautodetect::{self as autoconfig, xml};

fn check_tree(e: &xml::Element, lim: &xml::Limits, depth: usize) -> usize {
    assert!(depth <= lim.max_depth, "depth bound");
    assert!(e.name.len() <= lim.max_name_len, "name bound");
    assert!(
        e.attrs.len() <= lim.max_attrs_per_element,
        "attr count bound"
    );
    let mut n = 1;
    for c in &e.children {
        match c {
            xml::Node::Element(ch) => n += check_tree(ch, lim, depth + 1),
            xml::Node::Text(t) => assert!(t.len() <= lim.max_total_text, "text bound"),
        }
    }
    n
}

fuzz_target!(|data: &[u8]| {
    let lim = xml::Limits::AUTOCONFIG;
    let Ok((root, st)) = xml::parse(data, lim) else {
        return;
    };
    assert_eq!(check_tree(&root, &lim, 1), st.elements, "element count");
    assert!(st.elements <= lim.max_elements);
    let ser = xml::serialize(&root);
    let relaxed = xml::Limits {
        max_bytes: lim.max_bytes * 8,
        max_text_len: lim.max_total_text * 8,
        max_total_text: lim.max_total_text * 8,
        max_attr_value_len: lim.max_attr_value_len * 8,
        ..lim
    };
    let (again, _) = xml::parse(ser.as_bytes(), relaxed).expect("serialized tree must reparse");
    assert_eq!(again, root, "round trip");
    if let Ok(c) = autoconfig::from_autoconfig(&root, "example.org") {
        for s in c.imap.iter().chain(c.smtp.iter()) {
            assert!(autoconfig::valid_host(&s.host), "host validated");
            assert!(autoconfig::MAIL_PORTS.contains(&s.port), "port allowlisted");
        }
        assert!(c.imap.len() <= autoconfig::MAX_SERVERS && c.smtp.len() <= autoconfig::MAX_SERVERS);
        assert!(c.dropped.len() <= autoconfig::MAX_DROPPED);
    }
});
