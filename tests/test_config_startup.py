import os
import shlex
import subprocess
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from agent_messenger.config import load_config


def _write_credential(directory: Path, name: str, value: bytes) -> None:
    path = directory / name
    path.write_bytes(value)
    path.chmod(0o400)


def _fixture_config(tmp_path: Path) -> tuple[Path, Path]:
    credentials = tmp_path / "credentials"
    credentials.mkdir(mode=0o700)
    _write_credential(credentials, "cursor-key", b"cursor-" + b"0" * 40)
    _write_credential(credentials, "encryption-key", Fernet.generate_key())
    _write_credential(credentials, "proxy-channel-key", b"c" * 43)
    _write_credential(
        credentials, "proxy-introspection-client", b"inspector:" + b"x" * 32
    )

    config = tmp_path / "config.toml"
    config.write_text(
        """[service]
mode = "proxy"
database = "state/messages.sqlite3"
resource_uri = "https://messenger.example/"
proxy_introspection_port = 18766
proxy_channel_credential = "proxy-channel-key"
proxy_introspection_credential = "proxy-introspection-client"
cursor_credential = "cursor-key"
encryption_credential = "encryption-key"

[[agents]]
id = "agent_a"
address = "assistant-a@example.test"
label = "Assistant A"
mode = "mcp_event"
principal = "principal-a"
enabled = true
oauth_client_id = "client-a"
oauth_subject = "shared-subject"
""",
        encoding="utf-8",
    )
    return config, credentials


def _unit_directive(unit_path: Path, name: str) -> str:
    prefix = f"{name}="
    values = [
        line.removeprefix(prefix)
        for line in unit_path.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    assert len(values) == 1
    return values[0]


def test_full_load_config_and_execstartpre_without_legacy_pem(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    config_path, credentials = _fixture_config(tmp_path)
    config_text = config_path.read_text(encoding="utf-8")
    assert "proxy_public_key_credential" not in config_text

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    config = load_config(config_path)
    assert config.proxy_oauth is not None
    assert config.proxy_oauth.jwks_client.uri == (
        "http://127.0.0.1:18766/.well-known/jwks.json"
    )
    assert config.agents[0].principal == "principal-a"

    unit = repo_root / "deploy" / "agent-messenger.service"
    configured_env = _unit_directive(unit, "Environment")
    env_name, _ = configured_env.split("=", 1)
    pre = shlex.split(_unit_directive(unit, "ExecStartPre"))
    assert pre[1:] == ["-m", "agent_messenger.maintenance", "init"]
    assert Path(pre[0]).name == "python"

    env = os.environ.copy()
    env[env_name] = str(config_path)
    env["CREDENTIALS_DIRECTORY"] = str(credentials)
    source = str(repo_root / "src")
    env["PYTHONPATH"] = source + os.pathsep + env.get("PYTHONPATH", "")
    pre[0] = sys.executable
    completed = subprocess.run(
        pre,
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert '"initialized": true' in completed.stdout
    assert config.database.is_file()
