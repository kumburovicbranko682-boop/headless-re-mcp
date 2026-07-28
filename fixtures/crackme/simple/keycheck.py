#!/usr/bin/env python3
"""Simple KeyCheck Crackme — local UI license check (easy, no valid key)."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox


def check_key(user_key: str) -> bool:
    """Patched: accept any non-empty key (original always returned False)."""
    return bool(user_key.strip())


class KeyCheckApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("KeyCheck Crackme v1.0")
        self.geometry("420x220")
        self.resizable(False, False)
        self.configure(bg="#1e1e2e")

        tk.Label(
            self,
            text="KeyCheck Crackme",
            font=("Segoe UI", 16, "bold"),
            fg="#cdd6f4",
            bg="#1e1e2e",
        ).pack(pady=(24, 4))

        tk.Label(
            self,
            text="Enter license key to unlock",
            font=("Segoe UI", 10),
            fg="#a6adc8",
            bg="#1e1e2e",
        ).pack(pady=(0, 16))

        row = tk.Frame(self, bg="#1e1e2e")
        row.pack()

        tk.Label(row, text="Key:", font=("Segoe UI", 11), fg="#cdd6f4", bg="#1e1e2e").pack(
            side=tk.LEFT, padx=(0, 8)
        )

        self.entry = tk.Entry(
            row,
            width=24,
            font=("Consolas", 12),
            bg="#313244",
            fg="#cdd6f4",
            insertbackground="#cdd6f4",
            relief=tk.FLAT,
        )
        self.entry.pack(side=tk.LEFT)
        self.entry.bind("<Return>", lambda _e: self.on_verify())
        self.entry.focus_set()

        tk.Button(
            self,
            text="Verify",
            font=("Segoe UI", 11, "bold"),
            bg="#89b4fa",
            fg="#1e1e2e",
            activebackground="#74c7ec",
            relief=tk.FLAT,
            padx=16,
            pady=4,
            command=self.on_verify,
        ).pack(pady=20)

        self.status = tk.Label(
            self,
            text="",
            font=("Segoe UI", 10),
            fg="#a6adc8",
            bg="#1e1e2e",
        )
        self.status.pack()

    def on_verify(self) -> None:
        key = self.entry.get()
        if not key.strip():
            self.status.config(text="Please enter a key.", fg="#f9e2af")
            return
        if check_key(key):
            self.status.config(text="SUCCESS - license accepted.", fg="#a6e3a1")
            messagebox.showinfo("Success", "Correct key! Crackme solved.")
        else:
            self.status.config(text="FAILED - invalid license key.", fg="#f38ba8")
            messagebox.showerror("Failed", "Wrong key. Try again.")


def main() -> None:
    app = KeyCheckApp()
    app.mainloop()


if __name__ == "__main__":
    main()