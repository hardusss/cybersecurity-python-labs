"""Допоміжні функції для охайного виводу в консоль."""

from collections.abc import Sequence

LINE_WIDTH = 79


def print_section(title: str) -> None:
    """Друкує заголовок розділу між двома лініями."""
    print()
    print("=" * LINE_WIDTH)
    print(title)
    print("=" * LINE_WIDTH)


def print_table(
    headers: Sequence[str], rows: Sequence[Sequence[object]]
) -> None:
    """Друкує дані у вигляді текстової таблиці з рамкою."""
    cells = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in cells:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def format_row(row: Sequence[str]) -> str:
        parts = (
            cell.ljust(width) for cell, width in zip(row, widths, strict=True)
        )
        return "| " + " | ".join(parts) + " |"

    print(border)
    print(format_row(headers))
    print(border)
    for row in cells:
        print(format_row(row))
    print(border)
