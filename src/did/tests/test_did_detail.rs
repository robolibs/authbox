use super::super::*;

#[test]
fn did_detail_namespace_exposes_key_jwk_and_x509_helpers() {
    assert_eq!(detail::MULTICODEC_ED25519_PUB, [0xed, 0x01]);
    assert_eq!(detail::MULTICODEC_X25519_PUB, [0xec, 0x01]);
    assert_eq!(detail::base58_value('1'), 0);
    assert_eq!(detail::base58_value('z'), 57);
    assert_eq!(detail::base58_value('0'), -1);

    let payload = [0xed, 0x01, 1, 2, 3, 4, 5];
    let encoded = detail::base58btc_encode(&payload);
    assert_eq!(detail::base58btc_decode(&encoded).unwrap(), payload);
    assert_eq!(detail::base58btc_encode(&[]), "1");

    let bytes = b"did-detail";
    let encoded_key = detail::base64url_encode_key(bytes);
    assert_eq!(encoded_key, detail::base64url_encode(bytes));
    assert_eq!(detail::base64url_decode(&encoded_key).unwrap(), bytes);

    assert_eq!(
        detail::canonicalize_jwk_json(r#"{"x":"abc","kty":"OKP","crv":"Ed25519"}"#).unwrap(),
        r#"{"crv":"Ed25519","kty":"OKP","x":"abc"}"#
    );

    let refs = vec![
        "did:web:example#0".to_string(),
        "did:web:example#1".to_string(),
    ];
    assert!(detail::has_reference(&refs, "did:web:example#1"));
    assert!(!detail::has_reference(&refs, "did:web:example#missing"));
}

#[test]
fn did_detail_namespace_exposes_document_json_helpers() {
    let value = crate::json::parse(
        r#"{
            "id": "did:example:123",
            "list": ["a", 1, "b"],
            "jwk": {"kty":"OKP","crv":"Ed25519","x":"abc","y":"def"},
            "endpoint": {"uri":"https://agent.example","priority":1,"ok":true,"tags":["a",false]}
        }"#,
    )
    .unwrap();

    assert_eq!(
        detail::parse_required_string_field(&value, "id").unwrap(),
        "did:example:123"
    );
    let missing = detail::parse_required_string_field(&value, "missing").unwrap_err();
    assert_eq!(missing.message, "Missing required field: missing");
    let not_string = detail::parse_required_string_field(&value, "list").unwrap_err();
    assert_eq!(not_string.message, "Field is not a string: list");

    assert_eq!(
        detail::parse_string_array(detail::find_object_field(&value, "list")),
        vec!["a".to_string(), "b".to_string()]
    );

    let jwk = detail::parse_jwk(detail::find_object_field(&value, "jwk").unwrap()).unwrap();
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    assert_eq!(jwk.x, "abc");
    assert_eq!(jwk.y, "def");

    assert_eq!(
        detail::json_value_to_string(detail::find_object_field(&value, "endpoint")),
        r#"{"ok":true,"priority":1,"tags":["a",false],"uri":"https://agent.example"}"#
    );
    assert_eq!(detail::json_value_to_string(None), "null");
}
