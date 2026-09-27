"""Завдання 3: безпечне хешування, CSV-база та JSON-логування."""

import csv
import hashlib
import hmac
import json
from datetime import datetime
from functools import wraps
from pathlib import Path

from shared.console import print_section, print_table
from shared.student import VARIANT_NUMBER

# Параметри для варіанту 9
HASH_ALGORITHM = "sha224"
MIN_PASSWORD_LENGTH = 13
SALT_LENGTH = 5
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(SALT_LENGTH)

DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"
CSV_FIELDS = ("username", "password_hash")
MASK = "***"

users_to_register = (
    ("cloud_architect", "Cl0ud@Architect26"),
    ("devops_engineer", "D3vOps#Pipeline!"),
    ("qa_tester", "Qa_T3ster@Staging"),
    ("partner_access", "Partn3r$Access2026"),
    ("sec_analyst", "S3c@Analyst_Lviv"),
    ("sre_oncall", "Sre#OnCall2026!"),
    ("data_engineer", "D@ta_Engineer99"),
    ("net_admin", "N3tAdmin@Router7"),
    ("soc_operator", "S0c!Operator2026"),
    ("pentester", "P3nT3st@Red_Team"),
)

# База користувачів, зчитана з CSV
users_db: list[dict[str, str]] = []


class ValidationError(Exception):
    """Пароль не відповідає вимогам безпеки."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає hex-хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за {MIN_PASSWORD_LENGTH} символів"
        )
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з хешем пароля."""
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list: tuple[tuple[str, str], ...]) -> int:
    """Записує користувачів у CSV-файл і повертає їхню кількість."""
    saved = 0
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with USERS_FILE.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(CSV_FIELDS)
            for username, password in users_list:
                try:
                    writer.writerow(create_user(username, password))
                    saved += 1
                except (ValueError, ValidationError) as error:
                    print(f"Пропущено {username}: {error}")
    except FileNotFoundError:
        print(f"Помилка: шлях {USERS_FILE} не знайдено")
    except PermissionError:
        print(f"Помилка: немає прав на запис у {USERS_FILE}")
    except IOError as error:
        print(f"Помилка вводу-виводу: {error}")
    return saved


def read_users() -> list[dict[str, str]]:
    """Зчитує базу користувачів з CSV-файлу."""
    try:
        with USERS_FILE.open(newline="", encoding="utf-8") as file:
            return list(csv.DictReader(file))
    except FileNotFoundError:
        print(f"Помилка: файл {USERS_FILE} не знайдено")
    except PermissionError:
        print(f"Помилка: немає прав на читання {USERS_FILE}")
    except IOError as error:
        print(f"Помилка вводу-виводу: {error}")
    return []


def load_users_db() -> None:
    """Оновлює users_db даними з CSV-файлу."""
    users_db.clear()
    users_db.extend(read_users())


def print_users_db() -> None:
    """Виводить базу користувачів у вигляді таблиці."""
    rows = [
        (number, user["username"], user["password_hash"])
        for number, user in enumerate(users_db, start=1)
    ]
    print_table(("№", "Логін", f"Хеш пароля ({HASH_ALGORITHM})"), rows)


def read_log() -> list[dict]:
    """Зчитує журнал подій, якщо він уже існує."""
    try:
        with LOG_FILE.open(encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print("Журнал пошкоджено, буде створено новий")
        return []
    return data if isinstance(data, list) else []


def write_log_entry(entry: dict) -> None:
    """Додає подію в JSON-журнал."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        entries = read_log()
        entries.append(entry)
        with LOG_FILE.open("w", encoding="utf-8") as file:
            json.dump(entries, file, ensure_ascii=False, indent=4)
    except FileNotFoundError:
        print(f"Помилка: шлях {LOG_FILE} не знайдено")
    except PermissionError:
        print(f"Помилка: немає прав на запис у {LOG_FILE}")
    except IOError as error:
        print(f"Помилка вводу-виводу: {error}")


def mask_arguments(args: tuple, kwargs: dict) -> tuple[list, dict]:
    """Приховує пароль, щоб він не потрапив у журнал."""
    safe_args = [args[0], *[MASK] * (len(args) - 1)] if args else []
    safe_kwargs = {
        key: MASK if key == "password" else value
        for key, value in kwargs.items()
    }
    return safe_args, safe_kwargs


def log_event(func):
    """Декоратор, що записує кожну спробу входу в log.json."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "")
        success = False
        try:
            success = func(*args, **kwargs)
            return success
        finally:
            safe_args, safe_kwargs = mask_arguments(args, kwargs)
            write_log_entry(
                {
                    "event": func.__name__,
                    "user": username,
                    "result": "success" if success else "failure",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "args": safe_args,
                    "kwargs": safe_kwargs,
                }
            )

    return wrapper


def find_hash(username: str) -> str | None:
    """Шукає збережений хеш пароля користувача в users_db."""
    for user in users_db:
        if user["username"] == username:
            return user["password_hash"]
    return None


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін і пароль користувача."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")

    stored_hash = find_hash(username)
    if stored_hash is None:
        return False
    try:
        entered_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False
    # Порівняння за сталий час захищає від атак за часом відповіді
    return hmac.compare_digest(entered_hash, stored_hash)


def demo_errors() -> None:
    """Показує обробку ValueError та ValidationError."""
    cases = (
        ("порожній пароль", "", PERSONAL_SALT),
        ("порожня сіль", "LongEnough@Pass1", ""),
        ("короткий пароль", "Short@Pass1", PERSONAL_SALT),
    )
    for title, password, salt in cases:
        try:
            generate_hash(password, salt)
        except ValidationError as error:
            print(f"  {title}: ValidationError - {error}")
        except ValueError as error:
            print(f"  {title}: ValueError - {error}")


def demo_salt() -> None:
    """Показує, як сіль змінює хеш того самого пароля."""
    password = "Cl0ud@Architect26"
    for salt in ("00000", PERSONAL_SALT):
        print(f"  сіль {salt}: {generate_hash(password, salt)}")


def demo_logins() -> None:
    """Виконує кілька спроб входу і виводить результат."""
    attempts = (
        ("cloud_architect", "Cl0ud@Architect26"),
        ("devops_engineer", "Wrong@Password123"),
        ("unknown_user", "Some@Password2026"),
        ("qa_tester", "short"),
        ("", "Empty@Username2026"),
        ("pentester", "P3nT3st@Red_Team"),
    )
    for username, password in attempts:
        try:
            result = login(username, password)
            status = "успішний вхід" if result else "відмова"
        except ValueError as error:
            status = f"ValueError - {error}"
        print(f"  login({username!r}) -> {status}")


def print_last_log_entries(count: int) -> None:
    """Виводить останні записи журналу."""
    entries = read_log()[-count:]
    print(json.dumps(entries, ensure_ascii=False, indent=4))


def main() -> None:
    """Запускає реєстрацію, читання бази та автентифікацію."""
    print_section("Завдання 3. Хешування, CSV-база та JSON-логування")
    print(
        f"Алгоритм: {HASH_ALGORITHM}, мінімальна довжина пароля: "
        f"{MIN_PASSWORD_LENGTH}, персональна сіль: '{PERSONAL_SALT}'"
    )
    print()

    print("Перевірка обробки помилок generate_hash:")
    demo_errors()
    print()

    print("Вплив солі на хеш одного пароля:")
    demo_salt()
    print()

    saved = create_users(users_to_register)
    print(f"Зареєстровано користувачів: {saved}, файл: {USERS_FILE.name}")
    print()

    load_users_db()
    print("Вміст users.csv (users_db):")
    print_users_db()
    print()

    print("Спроби входу:")
    demo_logins()
    print()

    print(f"Останні записи {LOG_FILE.name}:")
    print_last_log_entries(3)


if __name__ == "__main__":
    main()
