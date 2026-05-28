from __future__ import annotations

import glob
import json
import os
import platform
from pathlib import Path

from crypto_utils import verify_license_signature
from license_tool import LICENSE_FILENAME, PRODUCT_ID


class HardwareKeyError(Exception):
    pass


def _canonical_payload(license_data_without_signature: dict) -> bytes:
    return json.dumps(
        license_data_without_signature,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def candidate_license_paths(manual_path: str | None = None) -> list[Path]:
    candidates: list[Path] = []

    if manual_path:
        path = Path(manual_path)
        if path.is_dir():
            candidates.append(path / LICENSE_FILENAME)
        else:
            candidates.append(path)
        return candidates

    system = platform.system()

    if system == "Windows":
        for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
            candidates.append(Path(f"{letter}:/{LICENSE_FILENAME}"))
    elif system == "Darwin":
        for path in glob.glob(f"/Volumes/*/{LICENSE_FILENAME}"):
            candidates.append(Path(path))
    else:
        user = os.getenv("USER") or ""
        patterns = [
            f"/media/{user}/*/{LICENSE_FILENAME}",
            f"/run/media/{user}/*/{LICENSE_FILENAME}",
            f"/mnt/*/{LICENSE_FILENAME}",
        ]
        for pattern in patterns:
            for path in glob.glob(pattern):
                candidates.append(Path(path))

    return candidates


def load_and_validate_license(path: Path) -> dict:
    if not path.exists():
        raise HardwareKeyError(f"Файл лицензии не найден: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            license_data = json.load(file)
    except json.JSONDecodeError as exc:
        raise HardwareKeyError("Файл лицензии повреждён или не является JSON") from exc

    signature = license_data.get("signature")
    if not signature:
        raise HardwareKeyError("В лицензии отсутствует подпись")

    payload = dict(license_data)
    payload.pop("signature", None)

    if payload.get("product") != PRODUCT_ID:
        raise HardwareKeyError("Лицензия выпущена для другого продукта")

    if not verify_license_signature(_canonical_payload(payload), signature):
        raise HardwareKeyError("Подпись лицензии неверна")

    if not payload.get("license_id"):
        raise HardwareKeyError("В лицензии отсутствует license_id")

    return license_data


def find_hardware_key(manual_path: str | None = None) -> tuple[Path, dict]:
    errors = []

    for path in candidate_license_paths(manual_path):
        try:
            license_data = load_and_validate_license(path)
            return path, license_data
        except HardwareKeyError as exc:
            errors.append(str(exc))

    if manual_path:
        details = "; ".join(errors) if errors else "путь не проверен"
        raise HardwareKeyError(f"Аппаратный ключ не найден или некорректен: {details}")

    raise HardwareKeyError("Аппаратный ключ не найден. Укажите путь параметром --key-path")
