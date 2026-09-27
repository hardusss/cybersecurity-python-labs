"""Головний файл лабораторної роботи №1.

Запуск з кореня репозиторію:
    python -m labs.lab01.main
"""

from labs.lab01 import task1, task2, task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main() -> None:
    """Послідовно запускає всі три завдання."""
    print("Лабораторна робота №1")
    print("Основи розробки на Python, Git та стандарти стилю коду")
    print(f"{STUDENT_NAME}, {GROUP_NAME}, варіант {VARIANT_NUMBER}")

    task1.main()
    task2.main()
    task3.main()


if __name__ == "__main__":
    main()
