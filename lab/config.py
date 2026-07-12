import sys
from pathlib import Path
from pydantic_settings import BaseSettings

# editable install: lab/config.py lives at project_root/lab/config.py
_ENV_FILE = Path(__file__).parent.parent / ".env"


class Settings(BaseSettings):
    proxmox_host: str = ""
    proxmox_port: int = 8006
    proxmox_token_id: str = ""
    proxmox_token_secret: str = ""
    proxmox_verify_ssl: bool = False
    proxmox_storage: str = ""
    templates_dir: str = "/var/lib/lab-platform/templates"
    build_sources_dir: str = "/var/lib/lab-platform/build-sources"

    # VMID of the management VM itself. setup.sh creates it as 100 by convention —
    # override only if that VM was recreated under a different VMID (e.g. a manual
    # reinstall that didn't reuse 100).
    mgmt_vmid: int = 100

    db_url: str = ""
    secret_key: str = ""

    deploy_ssh_timeout: int = 300
    web_url: str = ""

    model_config = {"env_file": str(_ENV_FILE), "extra": "ignore"}


def get_settings() -> Settings:
    return Settings()


def require_proxmox(s: Settings) -> None:
    missing = [
        key
        for key, val in {
            "PROXMOX_HOST": s.proxmox_host,
            "PROXMOX_TOKEN_ID": s.proxmox_token_id,
            "PROXMOX_TOKEN_SECRET": s.proxmox_token_secret,
        }.items()
        if not val
    ]
    if missing:
        for key in missing:
            print(
                f"error: {key} is not set — fill in .env before running lab commands",
                file=sys.stderr,
            )
        raise SystemExit(1)
