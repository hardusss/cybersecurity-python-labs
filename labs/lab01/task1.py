"""Завдання 1: комплексний аналізатор надійності паролів (варіант 9)."""

import random
import string
from collections import Counter

from shared.console import print_section, print_table
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані для варіанту 9
passwords = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {
    "plain",
    "member",
    "regular",
    "ordinary",
    "usual",
    "user",
}

DUPLICATES_COUNT = 3
VERY_STRONG_BONUS = 4
SPECIAL_CHARS = frozenset(string.punctuation)

# Який ключ критерію відповідає якій групі символів
REQUIRED_GROUPS = {
    "require_digits": "digit",
    "require_upper": "upper",
    "require_special": "special",
}

FORBIDDEN = "Заборонений"
WEAK = "Слабкий"
MEDIUM = "Середній"
STRONG = "Сильний"
VERY_STRONG = "Дуже сильний"
RATINGS_ORDER = (FORBIDDEN, WEAK, MEDIUM, STRONG, VERY_STRONG)

# Додаткові паролі не з варіанту: показують категорії,
# які не трапляються у вхідних даних
EXTRA_PASSWORDS = ["cybersecurity", "Forensics2023", "Lab@Pass1"]


def add_duplicates(
    source: list[str], count: int = DUPLICATES_COUNT
) -> tuple[list[str], list[int]]:
    """Дописує в кінець списку копії паролів з випадковими індексами."""
    indexes = random.sample(range(len(source)), count)
    duplicates = [source[index] for index in indexes]
    return source + duplicates, indexes


def get_char_groups(password: str) -> dict[str, bool]:
    """Визначає, які групи символів присутні в паролі."""
    return {
        "digit": any(char.isdigit() for char in password),
        "upper": any(char.isupper() for char in password),
        "lower": any(char.islower() for char in password),
        "special": any(char in SPECIAL_CHARS for char in password),
    }


def meets_all_criteria(groups: dict[str, bool], rules: dict) -> bool:
    """Перевіряє, чи виконані всі обов'язкові критерії варіанту."""
    return all(
        groups[group]
        for rule, group in REQUIRED_GROUPS.items()
        if rules.get(rule)
    )


def rate_password(
    password: str, occurrences: int, rules: dict, forbidden: set[str]
) -> str:
    """Повертає оцінку надійності пароля."""
    min_length = rules["min_length"]
    if password.lower() in forbidden or len(password) < min_length:
        return FORBIDDEN

    groups = get_char_groups(password)
    if meets_all_criteria(groups, rules):
        is_long = len(password) >= min_length + VERY_STRONG_BONUS
        # Повторно використаний пароль не може бути "Дуже сильним"
        if is_long and occurrences == 1:
            return VERY_STRONG
        return STRONG

    # Довжина нормальна, але виконані не всі критерії
    if sum(groups.values()) >= 2:
        return MEDIUM
    return WEAK


def analyze_passwords(
    items: list[str], rules: dict, forbidden: set[str]
) -> list[dict]:
    """Аналізує кожен пароль і повертає список результатів."""
    counts = Counter(items)
    normalized_forbidden = {word.lower() for word in forbidden}
    results = []
    for number, password in enumerate(items, start=1):
        groups = get_char_groups(password)
        results.append(
            {
                "number": number,
                "password": password,
                "length": len(password),
                "groups": groups,
                "count": counts[password],
                "rating": rate_password(
                    password, counts[password], rules, normalized_forbidden
                ),
            }
        )
    return results


def mark(value: bool) -> str:
    """Перетворює логічне значення на позначку для таблиці."""
    return "+" if value else "-"


def print_results(results: list[dict]) -> None:
    """Виводить результати аналізу у вигляді таблиці."""
    headers = (
        "№",
        "Пароль",
        "Довж.",
        "Цифра",
        "Велика",
        "Мала",
        "Спец.",
        "Повт.",
        "Оцінка",
    )
    rows = [
        (
            item["number"],
            item["password"],
            item["length"],
            mark(item["groups"]["digit"]),
            mark(item["groups"]["upper"]),
            mark(item["groups"]["lower"]),
            mark(item["groups"]["special"]),
            item["count"],
            item["rating"],
        )
        for item in results
    ]
    print_table(headers, rows)


def print_summary(results: list[dict]) -> None:
    """Виводить кількість паролів у кожній категорії."""
    stats = Counter(item["rating"] for item in results)
    print("Підсумок за категоріями:")
    for rating in RATINGS_ORDER:
        print(f"  {rating:<13} {stats.get(rating, 0)}")


def main() -> None:
    """Запускає аналіз паролів для свого варіанту."""
    print_section("Завдання 1. Аналізатор надійності паролів")
    print(f"Студент: {STUDENT_NAME}, група {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")

    min_length = criteria["min_length"]
    print(
        f"Критерії: довжина від {min_length}, цифра, велика літера, спецсимвол"
    )
    print(
        f"Поріг для оцінки '{VERY_STRONG}': "
        f"{min_length + VERY_STRONG_BONUS} символів і унікальність"
    )

    full_list, indexes = add_duplicates(passwords)
    duplicated = [passwords[index] for index in indexes]
    print(f"Випадкові індекси дублікатів: {indexes}")
    print(f"Додані дублікати: {duplicated}")
    print()

    results = analyze_passwords(full_list, criteria, forbidden_passwords)
    print_results(results)
    print_summary(results)

    print()
    print("Додаткова перевірка (паролі не з варіанту):")
    extra = analyze_passwords(EXTRA_PASSWORDS, criteria, forbidden_passwords)
    print_results(extra)


if __name__ == "__main__":
    main()
