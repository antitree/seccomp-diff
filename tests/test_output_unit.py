"""Fast, hermetic smoke tests for the table output layer.

Integration tests in tests/test_seccomp.py require a running container/runtime.
These tests intentionally do not access Docker, Kubernetes or Linux ptrace.
"""
from common.output import CustomTable


def test_custom_table_tracks_rows():
    table = CustomTable()
    table.add_column("property")
    table.add_column("value")
    table.add_custom_row("defaultAction", "SCMP_ACT_ERRNO")
    assert len(table.rows) == 1
    row = table.get_custom_row(0)
    assert len(row) == 2
    assert row[0].text == "defaultAction"
    assert row[1].text == "SCMP_ACT_ERRNO"


def test_custom_table_preserves_multiple_rows():
    table = CustomTable()
    table.add_column("name")
    table.add_column("action")
    table.add_custom_row("read", "ALLOW")
    table.add_custom_row("mount", "ERRNO")
    assert table.get_custom_row(1)[0].text == "mount"
    assert table.get_custom_row(1)[1].text == "ERRNO"
