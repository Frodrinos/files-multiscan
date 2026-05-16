"""Color utilities for terminal output."""

from colorama import Fore, Style, init

init(autoreset=True)


LEVEL_COLORS = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.GREEN,
    "UNKNOWN": Fore.LIGHTBLACK_EX,
}

VERDICT_COLORS = {
    "malicious": Fore.RED,
    "suspicious": Fore.YELLOW,
    "clean": Fore.GREEN,
    "unknown": Fore.LIGHTBLACK_EX,
}


def color_level(level: str) -> str:
    """TReturn colorized risk level string."""
    color = LEVEL_COLORS.get(level, Fore.WHITE)
    return f"{color}{level}"


def color_verdict(verdict: str) -> str:
    """Return colorized verdict string."""
    color = VERDICT_COLORS.get(verdict, Fore.WHITE)
    return f"{color}{verdict}"


def header(text: str) -> str:
    """Return colorized header (cyan)."""
    return f"{Fore.CYAN}{text}"


def error_text(text: str) -> str:
    """Return colorized error (yellow)."""
    return f"{Fore.YELLOW}{text}"
