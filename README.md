Курсовой проект: применение аппаратных средств защиты программ

Запуск:


python src/license_tool.py usb_key --license-id USB-KEY-001 --owner "Пользователь"

python src/compiler.py examples/program.src build/program.bytecode

python src/protector.py build/program.bytecode build/protected_program.hpkg --license-id USB-KEY-001

python src/runtime.py build/protected_program.hpkg --key-path usb_key


Проверка защиты:

python src/runtime.py build/protected_program.hpkg

Если не найден файл `license.key`, запуск будет запрещён.

Как работает защита:

1. Транслятор читает файл `.src` и создаёт байткод.
2. Упаковщик шифрует байткод с использованием идентификатора лицензии.
3. Runtime ищет файл `license.key` на USB-носителе или в указанной папке.
4. Runtime проверяет подпись лицензии.
5. Если лицензия корректна, из неё берётся `license_id`.
6. На основе `license_id` расшифровывается байткод.
7. Интерпретатор выполняет команды.
