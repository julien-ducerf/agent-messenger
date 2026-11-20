import stat

import pytest

from agent_messenger.config import configured_message_retention_days, credential


def test_systemd_acl_credential_is_readable_from_private_unit_directory(
    tmp_path, monkeypatch
):
    path = tmp_path / "cursor-key"
    path.write_bytes(b"cursor-secret-material" * 2)
    path.chmod(0o440)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

    assert credential(tmp_path, "cursor-key", systemd_managed=True) == path.read_bytes()


@pytest.mark.parametrize("mode", [0o460, 0o444, 0o640, 0o4000])
def test_systemd_credential_rejects_permissions_outside_read_only_acl(mode, tmp_path, monkeypatch):
    path = tmp_path / "cursor-key"
    path.write_bytes(b"cursor-secret-material" * 2)
    path.chmod(mode)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))

    with pytest.raises(ValueError, match="systemd credentials require"):
        credential(tmp_path, "cursor-key", systemd_managed=True)


def test_systemd_credential_rejects_path_outside_systemd_directory(tmp_path, monkeypatch):
    credential_dir = tmp_path / "systemd"
    credential_dir.mkdir()
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    path = other_dir / "cursor-key"
    path.write_bytes(b"cursor-secret-material" * 2)
    path.chmod(0o440)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))

    with pytest.raises(ValueError, match="systemd credentials require"):
        credential(other_dir, "cursor-key", systemd_managed=True)


def test_regular_private_credential_still_requires_private_mode(tmp_path):
    path = tmp_path / "cursor-key"
    path.write_bytes(b"cursor-secret-material" * 2)
    path.chmod(0o440)

    with pytest.raises(ValueError, match="private regular files"):
        credential(tmp_path, "cursor-key")


def test_credentials_reject_symlinks(tmp_path):
    real_path = tmp_path / "real"
    real_path.write_bytes(b"cursor-secret-material" * 2)
    real_path.chmod(stat.S_IRUSR)
    (tmp_path / "cursor-key").symlink_to(real_path)

    with pytest.raises(ValueError, match="private regular files"):
        credential(tmp_path, "cursor-key")


def test_message_retention_setting_defaults_and_checks_bounds():
    assert configured_message_retention_days({}) == 7
    assert configured_message_retention_days({"message_retention_days": 2}) == 2
    for value in (0, 366, True, "7"):
        with pytest.raises(ValueError, match="message_retention_days"):
            configured_message_retention_days({"message_retention_days": value})
