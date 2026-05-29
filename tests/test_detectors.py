from ioc_triage.detectors import detect_ioc_type


def test_detect_ipv4():
    assert detect_ioc_type("192.0.2.10") == "ipv4"


def test_detect_domain():
    assert detect_ioc_type("example.com") == "domain"


def test_detect_url():
    assert detect_ioc_type("http://example.com/login") == "url"


def test_detect_md5():
    assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "md5"


def test_detect_sha256():
    assert detect_ioc_type(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ) == "sha256"


def test_detect_unknown():
    assert detect_ioc_type("not an ioc") == "unknown"


def test_invalid_ipv4():
    assert detect_ioc_type("999.999.999.999") == "unknown"


def test_invalid_domain_starting_with_hyphen():
    assert detect_ioc_type("-example.com") == "unknown"


def test_invalid_domain_ending_with_hyphen():
    assert detect_ioc_type("example-.com") == "unknown"