from __future__ import annotations

import argparse
import json
from pathlib import Path

from crypto_utils import decrypt_for_license
from hardware_key import HardwareKeyError, find_hardware_key


class RuntimeErrorInProgram(Exception):
    pass


def _resolve_value(value, variables: dict[str, int]) -> int:
    if isinstance(value, int):
        return value

    if isinstance(value, dict) and "var" in value:
        name = value["var"]
        if name not in variables:
            raise RuntimeErrorInProgram(f"Переменная '{name}' не определена")
        return variables[name]

    raise RuntimeErrorInProgram(f"Некорректный операнд: {value}")


def execute_bytecode(bytecode: dict) -> None:
    if bytecode.get("magic") != "HPBC":
        raise RuntimeErrorInProgram("Файл не является корректным байткодом")

    variables: dict[str, int] = {}

    for index, instruction in enumerate(bytecode.get("instructions", []), start=1):
        op = instruction.get("op")
        args = instruction.get("args", [])

        try:
            if op == "PRINT":
                print(args[0])

            elif op == "SET":
                name = args[0]
                variables[name] = _resolve_value(args[1], variables)

            elif op == "PRINT_VAR":
                name = args[0]
                if name not in variables:
                    raise RuntimeErrorInProgram(f"Переменная '{name}' не определена")
                print(variables[name])

            elif op in {"ADD", "SUB", "MUL", "DIV"}:
                left = _resolve_value(args[0], variables)
                right = _resolve_value(args[1], variables)

                if op == "ADD":
                    print(left + right)
                elif op == "SUB":
                    print(left - right)
                elif op == "MUL":
                    print(left * right)
                elif op == "DIV":
                    if right == 0:
                        raise RuntimeErrorInProgram("Деление на ноль")
                    print(left // right)

            else:
                raise RuntimeErrorInProgram(f"Неизвестная инструкция: {op}")
        except IndexError as exc:
            raise RuntimeErrorInProgram(f"Ошибка аргументов в инструкции {index}") from exc


def load_protected_package(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        package = json.load(file)

    if package.get("magic") != "HPKG":
        raise RuntimeErrorInProgram("Файл не является защищённым пакетом HPKG")

    return package


def main() -> None:
    parser = argparse.ArgumentParser(description="Запуск защищённой программы")
    parser.add_argument("package", help="Путь к защищённому .hpkg файлу")
    parser.add_argument(
        "--key-path",
        help="Путь к флешке/папке с license.key. Если не указан, выполняется автопоиск.",
    )
    args = parser.parse_args()

    try:
        key_path, license_data = find_hardware_key(args.key_path)
        license_id = license_data["license_id"]
        print(f"Аппаратный ключ найден: {key_path}")
        print(f"license_id: {license_id}")

        package = load_protected_package(Path(args.package))
        plain_bytecode = decrypt_for_license(package, license_id)
        bytecode = json.loads(plain_bytecode.decode("utf-8"))

        print("Доступ разрешён. Запуск программы:")
        print("-" * 40)
        execute_bytecode(bytecode)
        print("-" * 40)
        print("Программа завершена.")

    except HardwareKeyError as exc:
        print(f"Запуск запрещён: {exc}")
        raise SystemExit(1)
    except (OSError, json.JSONDecodeError, RuntimeErrorInProgram, ValueError) as exc:
        print(f"Ошибка выполнения: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
