import os
import json
import sqlite3
import subprocess
import base64
import hashlib
import hmac
import tkinter as tk
from tkinter import simpledialog, messagebox

CONFIG_FILE = 'config.json'
DB_FILE = 'passwords.db'
ITERATIONS = 200000


def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)


def verify_password(stored_hash: bytes, password: str, salt: bytes) -> bool:
    new_hash = hash_password(password, salt)
    return hmac.compare_digest(stored_hash, new_hash)


def encrypt_text(password: str, plaintext: str) -> str:
    result = subprocess.run(
        ['openssl', 'enc', '-aes-256-cbc', '-base64', '-pbkdf2', '-pass', f'pass:{password}'],
        input=plaintext.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode())
    return result.stdout.decode().strip()


def decrypt_text(password: str, ciphertext: str) -> str:
    result = subprocess.run(
        ['openssl', 'enc', '-d', '-aes-256-cbc', '-base64', '-pbkdf2', '-pass', f'pass:{password}'],
        input=ciphertext.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError('Decryption failed')
    return result.stdout.decode().strip()


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        'CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT, username TEXT, password TEXT)'
    )
    conn.commit()
    conn.close()


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, 'r') as f:
        data = json.load(f)
        data['salt'] = base64.b64decode(data['salt'])
        data['hash'] = base64.b64decode(data['hash'])
        return data


def save_config(password: str):
    salt = os.urandom(16)
    pwd_hash = hash_password(password, salt)
    data = {
        'salt': base64.b64encode(salt).decode(),
        'hash': base64.b64encode(pwd_hash).decode(),
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f)


def get_entries():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('SELECT id, service FROM entries')
    rows = cur.fetchall()
    conn.close()
    return rows


def get_entry(entry_id: int):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('SELECT service, username, password FROM entries WHERE id=?', (entry_id,))
    row = cur.fetchone()
    conn.close()
    return row


def add_entry(service: str, username: str, password: str, master_password: str):
    enc_username = encrypt_text(master_password, username)
    enc_password = encrypt_text(master_password, password)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute(
        'INSERT INTO entries (service, username, password) VALUES (?, ?, ?)',
        (service, enc_username, enc_password),
    )
    conn.commit()
    conn.close()


def delete_entry(entry_id: int):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('DELETE FROM entries WHERE id=?', (entry_id,))
    conn.commit()
    conn.close()


class PasswordManager(tk.Tk):
    def __init__(self, master_password: str):
        super().__init__()
        self.title('Password Manager')
        self.master_password = master_password

        self.listbox = tk.Listbox(self, width=40)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.listbox.bind('<Double-Button-1>', self.show_entry)

        btn_frame = tk.Frame(self)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y)

        tk.Button(btn_frame, text='Add', command=self.add_entry).pack(fill=tk.X)
        tk.Button(btn_frame, text='Delete', command=self.delete_selected).pack(fill=tk.X)
        tk.Button(btn_frame, text='Refresh', command=self.refresh).pack(fill=tk.X)

        self.refresh()

    def refresh(self):
        self.listbox.delete(0, tk.END)
        for entry_id, service in get_entries():
            self.listbox.insert(tk.END, f'{entry_id}: {service}')

    def add_entry(self):
        service = simpledialog.askstring('Service', 'Service name:')
        if not service:
            return
        username = simpledialog.askstring('Username', 'Username:')
        if username is None:
            return
        password = simpledialog.askstring('Password', 'Password:', show='*')
        if password is None:
            return
        add_entry(service, username, password, self.master_password)
        self.refresh()

    def show_entry(self, event=None):
        selection = self.listbox.curselection()
        if not selection:
            return
        idx = self.listbox.get(selection[0]).split(':')[0]
        data = get_entry(int(idx))
        if data:
            service, enc_user, enc_pass = data
            try:
                username = decrypt_text(self.master_password, enc_user)
                password = decrypt_text(self.master_password, enc_pass)
            except Exception:
                messagebox.showerror('Error', 'Failed to decrypt. Wrong master password?')
                return
            messagebox.showinfo(service, f'Username: {username}\nPassword: {password}')

    def delete_selected(self):
        selection = self.listbox.curselection()
        if not selection:
            return
        idx = self.listbox.get(selection[0]).split(':')[0]
        delete_entry(int(idx))
        self.refresh()


def first_setup():
    root = tk.Tk()
    root.withdraw()
    while True:
        pwd1 = simpledialog.askstring('Setup', 'Create master password:', show='*')
        if not pwd1:
            continue
        pwd2 = simpledialog.askstring('Setup', 'Confirm master password:', show='*')
        if pwd1 == pwd2:
            save_config(pwd1)
            messagebox.showinfo('Setup', 'Master password set.')
            root.destroy()
            return pwd1
        else:
            messagebox.showerror('Error', 'Passwords do not match.')


def login(config):
    root = tk.Tk()
    root.withdraw()
    for _ in range(3):
        pwd = simpledialog.askstring('Login', 'Enter master password:', show='*')
        if pwd and verify_password(config['hash'], pwd, config['salt']):
            root.destroy()
            return pwd
        else:
            messagebox.showerror('Error', 'Incorrect password.')
    root.destroy()
    return None


def main():
    init_db()
    config = load_config()
    if config is None:
        master_pwd = first_setup()
    else:
        master_pwd = login(config)
    if not master_pwd:
        return
    app = PasswordManager(master_pwd)
    app.mainloop()


if __name__ == '__main__':
    main()
