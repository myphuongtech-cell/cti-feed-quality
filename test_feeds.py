from src.feeds import parse_ip_list, parse_malwarebazaar, parse_openphish, parse_threatfox, parse_urlhaus

URLHAUS = """################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2026-10-21 08:10:00","http://evil.com/a.exe","online","2026-10-21 08:10:00","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/1/","rep"
"2","2026-10-21 08:11:00","http://5.6.7.8:80/b","offline","2026-10-21 08:11:00","malware_download","","https://urlhaus.abuse.ch/url/2/","rep"
# END
"""

THREATFOX = """################################################################
# ThreatFox IOCs: recent additions - CSV format                #
################################################################
#
# first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,malware_printable,last_seen_utc,confidence_level,is_compromised,reference,tags,anonymous,reporter
"2026-10-21 08:00:00", "100", "1.2.3.4:443", "ip:port", "botnet_cc", "win.x", "", "Some Bot", "", "75", "0", "", "", "0", "r"
"2026-10-21 08:01:00", "101", "bad-domain.com", "domain", "payload_delivery", "win.y", "", "Loader", "", "50", "0", "", "", "0", "r"
"2026-10-21 08:02:00", "102", "http://evil.org/x", "url", "payload_delivery", "win.y", "", "Loader", "", "50", "0", "", "", "0", "r"
"2026-10-21 08:03:00", "103", "44d88612fea8a8f36de82e1278abb02f", "md5_hash", "payload", "win.z", "", "Stealer", "", "50", "0", "", "", "0", "r"
"2026-10-21 08:04:00", "104", "weird", "unknown_type", "x", "", "", "", "", "", "", "", "", "", ""
"""

MALWAREBAZAAR = """################################################################
# MalwareBazaar recent malware samples (CSV)                   #
################################################################
#
# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh
"2026-10-21 07:00:00", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "44d88612fea8a8f36de82e1278abb02f", "3395856ce81f2b7382dee72602f798b642f14140", "r", "a.exe", "exe", "application/x-dosexec", "Emotet", "", "", "", "", ""
"""


def test_ip_list_with_comments_and_invalid_lines():
    df = parse_ip_list("# header\n1.2.3.4\n5.6.7.8 # note\nnot-an-ip\n\n9.9.9.9;x\n")
    assert list(df["ioc_value"]) == ["1.2.3.4", "5.6.7.8", "9.9.9.9"]
    assert set(df["ioc_type"]) == {"ip"}


def test_openphish():
    df = parse_openphish("https://a.pages.dev/login\nhttp://b.com/x\ngarbage\n")
    assert len(df) == 2 and set(df["ioc_type"]) == {"url"}


def test_urlhaus_header_in_comment():
    df = parse_urlhaus(URLHAUS)
    assert len(df) == 2
    assert df.iloc[0]["status"] == "online" and df.iloc[1]["status"] == "offline"
    assert df.iloc[0]["source_first_seen"] == "2026-10-21 08:10:00"


def test_threatfox_types_and_skip_unknown():
    df = parse_threatfox(THREATFOX)
    assert list(df["ioc_type"]) == ["ip", "domain", "url", "hash"]
    ip = df.iloc[0]
    assert ip["ioc_value"] == "1.2.3.4" and ip["port"] == "443" and ip["malware"] == "Some Bot"
    assert df.iloc[3]["hash_type"] == "md5"


def test_malwarebazaar_emits_sha256_and_md5_with_sample_id():
    df = parse_malwarebazaar(MALWAREBAZAAR)
    assert set(df["hash_type"]) == {"sha256", "md5"}
    assert set(df["sample_id"]) == {"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}
    assert set(df["malware"]) == {"Emotet"}
