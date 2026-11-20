"""Generate an isolated local configuration without printing credentials."""

import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

PROJECT = Path(__file__).resolve().parents[1]
LOCAL = PROJECT / ".local"


def main():
    old_mask = os.umask(0o077)
    try:
        LOCAL.mkdir(mode=0o700, exist_ok=True)
        config = LOCAL / "config.toml"
        directory = LOCAL / "credentials"
        directory.mkdir(mode=0o700, exist_ok=True)
        values = {
            "cursor-key": secrets.token_urlsafe(48).encode(),
            "encryption-key": Fernet.generate_key(),
            "admin-password": secrets.token_urlsafe(48).encode(),
            **{
                f"{agent}-token": secrets.token_urlsafe(48).encode()
                for agent in ("agent_b", "agent_c", "agent_a")
            },
        }
        for name, value in values.items():
            try:
                with (directory / name).open("xb") as file:
                    file.write(value + b"\n")
            except FileExistsError:
                pass
        try:
            with config.open("x") as target:
                template = (PROJECT / "config" / "config.example.toml").read_text()
                target.write(
                    template.replace('".local/data/', '"data/').replace(
                        '".local/credentials"', '"credentials"'
                    )
                )
        except FileExistsError:
            pass
        print("Local configuration:", config.relative_to(PROJECT))
        print("Credentials directory:", directory.relative_to(PROJECT))
    finally:
        os.umask(old_mask)


if __name__ == "__main__":
    main()
