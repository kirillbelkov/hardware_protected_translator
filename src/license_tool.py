from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from crypto_utils import sign_license_payload


PRODUCT_ID = "hardware-protected-translator"
LICENSE_FILENAME = "license.key"


def _canonical_payload(license_data: dict) -> bytes:
    return json.dumps(
        license_data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def create_license(license_id: str, owner: str) -> dict:
    license_data = {
        "product": PRODUCT_ID,
        "license_id": license_id,
        "owner": owner,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    license_data["signature"] = sign_license_payload(_canonical_payload(license_data))
    return license_data


def write_license(output_dir: Path, license_id: str, owner: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    license_path = output_dir / LICENSE_FILENAME
    license_data = create_license(license_id, owner)

    with license_path.open("w", encoding="utf-8") as file:
        json.dump(license_data, file, ensure_ascii=False, indent=2)

    return license_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Создание учебной лицензии license.key")
    parser.add_argument("output_dir", help="Папка, куда будет записан license.key")
    parser.add_argument("--license-id", required=True, help="Идентификатор лицензии")
    parser.add_argument("--owner", default="Coursework user", help="Владелец лицензии")
    args = parser.parse_args()

    license_path = write_license(Path(args.output_dir), args.license_id, args.owner)
    print(f"OK: лицензия создана: {license_path}")
    print(f"license_id: {args.license_id}")


if __name__ == "__main__":
    main()
