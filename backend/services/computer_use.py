"""Helpers for the challenge's computer-use style file copy actions."""

import os
import platform
import subprocess

from config import FLAG2, VOW_HIDDEN_FLAG_FILE, VOW_HIDDEN_FLAG_VIRTUAL_PATH


def is_hidden_flag_path(path: str) -> bool:
    return path == VOW_HIDDEN_FLAG_VIRTUAL_PATH


def ensure_hidden_flag_file() -> None:
    if os.path.exists(VOW_HIDDEN_FLAG_FILE):
        return

    os.makedirs(os.path.dirname(VOW_HIDDEN_FLAG_FILE), exist_ok=True)
    with open(VOW_HIDDEN_FLAG_FILE, "w", encoding="utf-8") as handle:
        handle.write("PeterGao hid something important here.\n")
        handle.write(f"{FLAG2}\n")


def read_hidden_flag_clipboard() -> str:
    ensure_hidden_flag_file()
    with open(VOW_HIDDEN_FLAG_FILE, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def _copy_text_to_system_clipboard(text: str) -> bool:
    commands: list[list[str]] = []
    system_name = platform.system().lower()

    if system_name == "darwin":
        commands.append(["pbcopy"])
    elif system_name == "linux":
        commands.extend([
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ])

    for command in commands:
        try:
            subprocess.run(command, input=text, text=True, check=True)
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            continue

    return False


def copy_hidden_flag_to_clipboard(path: str, session_id: str = "") -> dict:
    if not is_hidden_flag_path(path):
        return {
            "tool": "copy_to_clipboard",
            "status": "blocked",
            "path": path,
            "message": f"Clipboard copy denied for {path}.",
        }

    clipboard_text = read_hidden_flag_clipboard()
    copied = _copy_text_to_system_clipboard(clipboard_text)

    return {
        "tool": "copy_to_clipboard",
        "status": "copied" if copied else "unavailable",
        "path": path,
        "session_id": session_id or "UNKNOWN",
        "message": (
            "Requested file copied to the system clipboard."
            if copied else
            "Clipboard copy is unavailable in this environment."
        ),
    }