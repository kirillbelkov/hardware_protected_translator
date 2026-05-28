from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from crypto_utils import encrypt_for_license


PACKAGE_MAGIC = "HPKG"
PACKAGE_VERSION = 1


def protect_bytecode(bytecode_path: Path, output_path: Path, license_id: str) -> None:
    plain_data = bytecode_path.read_bytes()
    encrypted = encrypt_for_license(plain_data, license_id)

    package = {
        "magic": PACKAGE_MAGIC,
        "version": PACKAGE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "protection": "demo-usb-license-xor-hmac-sha256",
        **encrypted,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(package, file, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Создание защищённого файла байткода")
    parser.add_argument("bytecode", help="Путь к файлу байткода")
    parser.add_argument("output", help="Путь к защищённому .hpkg файлу")
    parser.add_argument(
        "--license-id",
        required=True,
        help="Идентификатор лицензии, под который защищается программа",
    )
    args = parser.parse_args()

    protect_bytecode(Path(args.bytecode), Path(args.output), args.license_id)
    print(f"OK: защищённый файл создан: {args.output}")
    print(f"Файл привязан к license_id: {args.license_id}")


if __name__ == "__main__":
    main()
