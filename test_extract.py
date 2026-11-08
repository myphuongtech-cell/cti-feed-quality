from src.extract import ContextFilter, extract_by_type, extract_iocs, refang


def values(text, **kw):
    return {(i.type, i.value) for i in extract_iocs(text, **kw)}


def test_refang_basic():
    assert refang("hxxps[:]//evil[.]com/a") == "https://evil.com/a"
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("bad(dot)org") == "bad.org"
    assert refang("hxxp[://]evil[.]net") == "http://evil.net"


def test_defanged_paragraph():
    text = "The loader contacts hxxps://evil[.]com/gate.php and 8[.]8[.]4[.]4, dropper from bad-site[.]org."
    v = values(text)
    assert ("url", "https://evil.com/gate.php") in v
    assert ("ip", "8.8.4.4") in v
    assert ("domain", "bad-site.org") in v


def test_private_and_version_ips_are_dropped():
    cf = ContextFilter()
    v = values("Internal 192.168.1.10 and 10.0.0.5, loopback 127.0.0.1, version 1.2.3.4, public 8.8.8.8", context_filter=cf)
    ips = {x for t, x in v if t == "ip"}
    assert ips == {"8.8.8.8"}


def test_baseline_regex_keeps_noise():
    # regex thuần (không refang, không validate, không lọc) giữ lại IP riêng
    v = values("host 192.168.1.10", refang_input=False, validate=False)
    assert ("ip", "192.168.1.10") in v


def test_url_trailing_punctuation():
    v = values("See (http://evil.com/x.exe), then http://bad.org/a?b=1.")
    urls = {x for t, x in v if t == "url"}
    assert urls == {"http://evil.com/x.exe", "http://bad.org/a?b=1"}


def test_url_host_not_extracted_twice():
    v = values("http://evil.com/a and 1.2.3.4 at http://5.6.7.8/p")
    assert ("domain", "evil.com") not in v
    assert ("ip", "5.6.7.8") not in v
    assert ("ip", "1.2.3.4") in v


def test_file_names_are_not_domains():
    v = values("It drops setup.exe, report.pdf and run.ps1 then contacts c2.example-bad.com")
    domains = {x for t, x in v if t == "domain"}
    assert domains == {"c2.example-bad.com"}


def test_reference_and_example_domains_filtered():
    cf = ContextFilter()
    text = "See attack.mitre.org and example.com, malicious host is evil-update.xyz"
    domains = {x for t, x in values(text, context_filter=cf) if t == "domain"}
    assert domains == {"evil-update.xyz"}


def test_hashes():
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    v = values(f"md5 {md5} sha1 {sha1} sha256 {sha256.upper()}")
    assert ("hash", md5) in v and ("hash", sha1) in v and ("hash", sha256) in v
    kinds = {i.hash_type for i in extract_iocs(f"{md5} {sha1} {sha256}")}
    assert kinds == {"md5", "sha1", "sha256"}


def test_empty_file_hash_and_digit_strings_dropped():
    empty = "d41d8cd98f00b204e9800998ecf8427e"
    digits = "12345678901234567890123456789012"
    assert not values(f"{empty} {digits}")


def test_dedup_and_by_type():
    out = extract_by_type("8.8.8.8 and 8.8.8.8 again, evil.com evil.com")
    assert out["ip"] == {"8.8.8.8"}
    assert out["domain"] == {"evil.com"}


def test_email_domain_not_extracted():
    assert not [i for i in extract_iocs("contact analyst@vendor.com") if i.type == "domain"]


def test_pages_dev_not_dropped_by_tranco_parent_matching(tmp_path):
    tr = tmp_path / "tranco.csv"
    tr.write_text("1,google.com\n2,pages.dev\n", encoding="utf-8")
    cf = ContextFilter(tranco_path=tr)
    domains = {x for t, x in values("host evil-site.pages.dev and pages.dev", context_filter=cf) if t == "domain"}
    assert "evil-site.pages.dev" in domains
    assert "pages.dev" not in domains
