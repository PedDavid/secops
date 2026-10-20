use digest_diff_2::scanner::{Scanner, parse_findings};
#[test]
fn grype_native_matches_are_preserved_and_deduplicated() {
    let record = r#"{"vulnerability":{"id":"CVE-2026-12345","namespace":"debian:12","severity":"High","dataSource":"https://security-tracker.debian.org/tracker/CVE-2026-12345","fix":{"state":"fixed","versions":["2.0"]}},"artifact":{"name":"openssl","version":"1.0","type":"deb","locations":[{"path":"/usr/lib"}]}}"#;
    let data = format!("{{\"matches\":[{record},{record}]}}");
    let fs = parse_findings(data.as_bytes()).unwrap();
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].package, "openssl");
    assert_eq!(fs[0].fix_versions, ["2.0"]);
    assert_eq!(
        fs[0].link(),
        "https://security-tracker.debian.org/tracker/CVE-2026-12345"
    );
}
#[test]
fn malformed_outputs_cannot_be_reported_as_no_vulnerabilities() {
    for raw in ["{}", "{\"matches\":null}", "{\"matches\":[{}]}"] {
        assert!(parse_findings(raw.as_bytes()).is_err(), "{raw}")
    }
    assert!(parse_findings(b"{\"matches\":[]}").unwrap().is_empty());
}
#[test]
fn registry_detection_handles_docker_defaults_and_explicit_hosts() {
    assert_eq!(Scanner::registry("postgres:18@sha256:abcd"), "docker.io");
    assert_eq!(
        Scanner::registry("library/postgres@sha256:abcd"),
        "docker.io"
    );
    assert_eq!(
        Scanner::registry("registry-1.docker.io/library/alpine@sha256:abcd"),
        "registry-1.docker.io"
    );
    assert_eq!(
        Scanner::registry("localhost:5000/image@sha256:abcd"),
        "localhost:5000"
    );
}
