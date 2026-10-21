from src.config_patcher import apply_commands
from tests.conftest import IOS_CONFIG


def test_delete_by_sequence_and_keep_trailing_end():
    out = apply_commands(IOS_CONFIG, ["configure terminal", "ip access-list extended ACL_WAN_IN", "no 30", "end"])
    assert " 30 permit tcp any host 200.45.112.18 eq 23" not in out
    assert out.strip().endswith("end")


def test_insert_by_sequence_keeps_order():
    out = apply_commands(IOS_CONFIG, ["ip access-list extended ACL_WAN_IN", "15 permit tcp any host 172.16.10.50 eq 80 log"])
    lines = [l.strip() for l in out.splitlines()]
    assert lines.index("10 permit tcp any 172.16.10.0 0.0.0.255 eq 443") < lines.index("15 permit tcp any host 172.16.10.50 eq 80 log") < lines.index("20 deny tcp any host 172.16.10.50 eq 443")


def test_new_blocks_go_before_trailing_end():
    out = apply_commands(IOS_CONFIG, ["ip access-list standard ACL_MGMT", "permit 192.168.1.0 0.0.0.255"])
    assert out.index("ip access-list standard ACL_MGMT") < out.rindex("end")
    assert " permit 192.168.1.0 0.0.0.255" in out


def test_reorder_same_sequence_replaces_rule():
    out = apply_commands(IOS_CONFIG, ["ip access-list extended ACL_WAN_IN", "no 10", "no 20",
                                      "10 deny tcp any host 172.16.10.50 eq 443", "20 permit tcp any 172.16.10.0 0.0.0.255 eq 443"])
    lines = [l.strip() for l in out.splitlines()]
    assert lines.index("10 deny tcp any host 172.16.10.50 eq 443") < lines.index("20 permit tcp any 172.16.10.0 0.0.0.255 eq 443")
    assert "20 deny tcp any host 172.16.10.50 eq 443" not in lines


def test_interface_context_adds_child():
    out = apply_commands(IOS_CONFIG, ["interface GigabitEthernet0/1", "ip access-group ACL_LAN_IN in"])
    idx = out.splitlines().index("interface GigabitEthernet0/1")
    assert "ip access-group ACL_LAN_IN in" in out.splitlines()[idx + 1:idx + 5][-1] or any("ACL_LAN_IN" in l for l in out.splitlines()[idx:idx + 5])
