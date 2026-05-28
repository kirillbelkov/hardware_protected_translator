from __future__ import annotations

import argparse
import json
from pathlib import Path


BYTECODE_MAGIC = "HPBC"
BYTECODE_VERSION = 1


class CompileError(Exception):
    pass


def _parse_value(token: str):
    try:
        return int(token)
    except ValueError:
        return {"var": token}


def compile_line(line: str, line_number: int) -> dict | None:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split()
    command = parts[0].lower()

    if command == "print":
        if len(parts) < 2:
            raise CompileError(f"Строка {line_number}: print требует текст")
        return {"op": "PRINT", "args": [" ".join(parts[1:])]}

    if command == "set":
        if len(parts) != 3:
            raise CompileError(f"Строка {line_number}: set требует имя и значение")
        name = parts[1]
        value = _parse_value(parts[2])
        return {"op": "SET", "args": [name, value]}

    if command in {"add", "sub", "mul", "div"}:
        if len(parts) != 3:
            raise CompileError(f"Строка {line_number}: {command} требует два операнда")
        return {
            "op": command.upper(),
            "args": [_parse_value(parts[1]), _parse_value(parts[2])],
        }

    if command == "printvar":
        if len(parts) != 2:
            raise CompileError(f"Строка {line_number}: printvar требует имя переменной")
        return {"op": "PRINT_VAR", "args": [parts[1]]}

    raise CompileError(f"Строка {line_number}: неизвестная команда '{command}'")


def compile_source(source_path: Path) -> dict:
    instructions = []

    with source_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            instruction = compile_line(line, line_number)
            if instruction is not None:
                instructions.append(instruction)

    return {
        "magic": BYTECODE_MAGIC,
        "version": BYTECODE_VERSION,
        "source": str(source_path.name),
        "instructions": instructions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Транслятор мини-языка в байткод")
    parser.add_argument("source", help="Путь к .src файлу")
    parser.add_argument("output", help="Путь для сохранения байткода")
    args = parser.parse_args()

    source_path = Path(args.source)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    bytecode = compile_source(source_path)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(bytecode, file, ensure_ascii=False, indent=2)

    print(f"OK: байткод создан: {output_path}")
    print(f"Команд скомпилировано: {len(bytecode['instructions'])}")


if __name__ == "__main__":
    main()
