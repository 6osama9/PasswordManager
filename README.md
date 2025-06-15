# Password Manager

This is a simple password manager written in Python 3. It uses a local SQLite database to store credentials and encrypts them using AES‑256 via `openssl`. A Tkinter GUI provides basic management functions.

## Features

- AES‑256 encryption of usernames and passwords
- Local SQLite database (`passwords.db`)
- Master password protection
- Add, view and delete entries through a simple GUI

## Usage

Run the application with Python 3:

```bash
python3 password_manager.py
```

On first launch you will be prompted to create a master password. Keep this password safe—entries are encrypted with it. Subsequent launches require the same master password to access your stored passwords.

## Requirements

The script relies on the `openssl` command available on most systems. No additional Python packages are required.
