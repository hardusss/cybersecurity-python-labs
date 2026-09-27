# cybersecurity-python-labs

Лабораторні роботи з Python у контексті задач кібербезпеки.

Студент: Клепар Данило Богданович, група КБ-203, варіант 9.

## Підготовка середовища

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Запуск

Усі команди виконуються з кореня репозиторію:

```bash
python -m labs.lab01.main        # усі завдання ЛР1
python -m labs.lab01.task1       # тільки завдання 1
```

## Перевірка стилю коду

```bash
ruff check .
ruff format .
```

Налаштування Ruff лежать у `ruff.toml` (довжина рядка 79 за PEP 8).

## Структура

```
shared/          спільні модулі (дані студента, вивід таблиць)
labs/lab01/      лабораторна робота №1
    task1.py     аналізатор надійності паролів
    task2.py     система контролю доступу
    task3.py     хешування, CSV-база та JSON-журнал
    data/        users.csv і log.json (створюються під час запуску,
                 не потрапляють у Git)
```
