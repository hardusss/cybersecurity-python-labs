"""Завдання 2: багаторівнева система контролю доступу (варіант 9)."""

from collections import Counter

from shared.console import print_section, print_table

# Вхідні дані для варіанту 9
users = {
    "cloud_architect": {
        "role": "cloud_security",
        "clearance": 4,
        "department": "Cloud",
        "active": True,
    },
    "devops_engineer": {
        "role": "devops",
        "clearance": 3,
        "department": "DevOps",
        "active": True,
    },
    "qa_tester": {
        "role": "quality_assurance",
        "clearance": 2,
        "department": "QA",
        "active": True,
    },
    "partner_access": {
        "role": "partner",
        "clearance": 2,
        "department": "Partnership",
        "active": True,
    },
    "migrated_user": {
        "role": "migrated",
        "clearance": 1,
        "department": "Migration",
        "active": False,
    },
}
resources = [
    ("cloud_configs", 4),
    ("deployment_pipelines", 3),
    ("test_environments", 2),
    ("partner_apis", 2),
    ("infrastructure_code", 4),
    ("shared_resources", 1),
    ("container_registry", 3),
    ("secrets_vault", 4),
    ("build_artifacts", 2),
    ("public_endpoints", 1),
]
security_levels = (
    "Development",
    "Staging",
    "Production",
    "Critical Infrastructure",
)
blocked_users = {"migrated_user", "container_breach", "pipeline_compromise"}

ALLOW = "ALLOW"
DENY = "DENY"


def level_name(level: int) -> str:
    """Повертає текстову назву числового рівня безпеки (1-4)."""
    return security_levels[level - 1]


def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """Перевіряє доступ користувача до ресурсу заданого рівня.

    Повертає пару (чи дозволено доступ, причина відмови).
    """
    user = users.get(username)
    if user is None:
        return False, "User not found"
    if username in blocked_users:
        return False, "User is blocked"
    if not user["active"]:
        return False, "Account inactive"
    if user["clearance"] >= resource_level:
        return True, ""
    return False, "Insufficient clearance"


def print_resources() -> None:
    """Виводить список ресурсів з текстовими рівнями безпеки."""
    rows = [(name, level, level_name(level)) for name, level in resources]
    print_table(("Ресурс", "Рівень", "Назва рівня"), rows)


def print_users() -> None:
    """Виводить користувачів системи та їхній рівень допуску."""
    rows = []
    for username, info in users.items():
        status = "active" if info["active"] else "inactive"
        if username in blocked_users:
            status += ", blocked"
        rows.append(
            (
                username,
                info["role"],
                info["department"],
                f"{info['clearance']} ({level_name(info['clearance'])})",
                status,
            )
        )
    headers = ("Користувач", "Роль", "Відділ", "Допуск", "Статус")
    print_table(headers, rows)


def run_access_checks(usernames: list[str]) -> Counter:
    """Перевіряє доступ кожного користувача до кожного ресурсу."""
    stats = Counter()
    for username in usernames:
        for resource_name, resource_level in resources:
            allowed, reason = check_access(username, resource_level)
            result = ALLOW if allowed else f"{DENY} ({reason})"
            print(f"user={username} resource={resource_name} -> {result}")
            stats[ALLOW if allowed else DENY] += 1
        print()
    return stats


def main() -> None:
    """Запускає перевірку доступу для свого варіанту."""
    print_section("Завдання 2. Багаторівнева система контролю доступу")

    print("Ресурси системи:")
    print_resources()
    print()
    print("Користувачі системи:")
    print_users()
    print(f"Заблоковані: {', '.join(sorted(blocked_users))}")
    print()

    # Заблоковані логіни, яких немає в users, теж перевіряємо,
    # щоб показати відмову "User not found"
    unknown = sorted(blocked_users - users.keys())
    stats = run_access_checks(list(users) + unknown)
    print(f"Усього перевірок: {sum(stats.values())}")
    print(f"ALLOW: {stats[ALLOW]}, DENY: {stats[DENY]}")


if __name__ == "__main__":
    main()
