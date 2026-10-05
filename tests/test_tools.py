import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import file_integrity  # noqa: E402
import password_audit  # noqa: E402
import port_scanner  # noqa: E402
import subnet_calc  # noqa: E402


# ---------- subnet_calc ----------
def test_describe_lab_vpc():
    d = subnet_calc.describe("10.0.0.0/16")
    assert d["netmask"] == "255.255.0.0"
    assert d["usable_hosts"] == 65534
    assert d["broadcast"] == "10.0.255.255"
    assert d["private"] is True


def test_describe_slash24():
    d = subnet_calc.describe("192.168.1.77/24")
    assert (d["network"], d["first_host"], d["last_host"]) == ("192.168.1.0", "192.168.1.1", "192.168.1.254")


def test_split():
    assert subnet_calc.split("192.168.1.0/24", 26) == [
        "192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26", "192.168.1.192/26"]


def test_vlsm_fits_and_no_overlap():
    import ipaddress
    plan = subnet_calc.vlsm("192.168.0.0/24", [100, 50, 20, 10])
    nets = [ipaddress.ip_network(s) for _, s in plan]
    for (hosts, _), net in zip(plan, nets):
        assert net.num_addresses - 2 >= hosts
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)


def test_vlsm_too_big():
    with pytest.raises(ValueError):
        subnet_calc.vlsm("192.168.0.0/28", [100])


# ---------- port_scanner ----------
def test_parse_ports():
    assert port_scanner.parse_ports("80, 22,20-23") == [20, 21, 22, 23, 80]
    with pytest.raises(ValueError):
        port_scanner.parse_ports("70000")


def test_scan_finds_local_listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"SSH-2.0-TestServer\r\n")
        conn.close()
    threading.Thread(target=serve, daemon=True).start()

    _, found = port_scanner.scan("127.0.0.1", [port], threads=1, timeout=1)
    srv.close()
    assert found and found[0][0] == port
    assert found[0][2].startswith("SSH-2.0")


# ---------- password_audit ----------
def test_weak_password_flagged():
    assert password_audit.rating("password1") == "VERY WEAK"
    assert any("common" in f for f in password_audit.findings("password1"))


def test_strong_password():
    pw = "t7#Lq!vR2^mZ9&xP"
    assert password_audit.rating(pw) == "STRONG"
    assert password_audit.findings(pw) == []


def test_keyboard_sequence_detected():
    assert any("keyboard" in f for f in password_audit.findings("Qwerty!2xLmP9z"))


# ---------- file_integrity ----------
def test_integrity_detects_changes(tmp_path):
    (tmp_path / "a.txt").write_text("alpha")
    (tmp_path / "b.txt").write_text("beta")
    base = file_integrity.snapshot(tmp_path)

    (tmp_path / "a.txt").write_text("ALPHA (tampered)")
    (tmp_path / "b.txt").unlink()
    (tmp_path / "c.txt").write_text("new")
    diff = file_integrity.compare(base, file_integrity.snapshot(tmp_path))
    assert diff == {"added": ["c.txt"], "removed": ["b.txt"], "modified": ["a.txt"]}
