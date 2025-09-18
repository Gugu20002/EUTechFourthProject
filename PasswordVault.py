"""
Secure Password Manager (single-file)
Features:
- OOP design: CryptoManager, DatabaseManager, PasswordGenerator, PasswordManagerGUI
- Uses SQLite (vault.db) to store entries
- Uses Fernet (cryptography) for symmetric encryption of passwords
- Master password unlocks the vault (PBKDF2HMAC-derived key + salt stored in DB)
- Add / Edit / Delete / Search / List / View (decrypt) entries
- Password generator
- Export to encrypted .txt backup

Requirements:
    pip install cryptography

Run:
    python password_manager.py

Notes:
- On first run you'll be prompted to create a master password. A salt and a verifier token are stored in the database meta table.
- Passwords are encrypted before storage.
- The code includes basic input validation and error handling.

This is a single-file reference implementation. For production use, review cryptography practices, consider OS secret stores, stronger key management, and secure memory handling.
"""

import sqlite3
import os
import sys
import json
import base64
import secrets
import string
import datetime
from dataclasses import dataclass
from typing import Optional, List, Tuple

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    print("Missing dependency: cryptography. Install with 'pip install cryptography'")
    raise

try:
    import tkinter as tk
    from tkinter import simpledialog, messagebox, filedialog
except Exception:
    print("tkinter is required (should be bundled with Python).")
    raise

DB_FILE = "vault.db"
VERIFIER_PLAINTEXT = b"password-manager-verifier-v1"


class CryptoManager:
    """Derive a Fernet key from a master password using PBKDF2HMAC and use Fernet for encryption."""

    def __init__(self, master_password: str, salt: bytes):
        if isinstance(master_password, str):
            master_password = master_password.encode("utf-8")
        self.master_password = master_password
        self.salt = salt
        self._fernet = Fernet(self._derive_key())

    def _derive_key(self) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=390000,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password))
        return key

    def encrypt(self, plaintext: str) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return self._fernet.encrypt(plaintext)

    def decrypt(self, token: bytes) -> str:
        try:
            plaintext = self._fernet.decrypt(token)
            return plaintext.decode("utf-8")
        except InvalidToken:
            raise ValueError("Decryption failed: invalid master password or corrupted data")


class DatabaseManager:
    """Handles SQLite database interactions and schema."""

    def __init__(self, db_path: str = DB_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value BLOB
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password_blob BLOB NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)
        self.conn.commit()

    # Meta helpers
    def get_meta(self, key: str) -> Optional[bytes]:
        cur = self.conn.cursor()
        cur.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: bytes):
        cur = self.conn.cursor()
        cur.execute("REPLACE INTO meta(key, value) VALUES(?,?)", (key, value))
        self.conn.commit()

    # Entry CRUD
    def add_entry(self, site: str, username: str, password_blob: bytes, notes: str = "") -> int:
        now = datetime.datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO entries (site, username, password_blob, notes, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (site, username, password_blob, notes, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_entry(self, entry_id: int, site: str, username: str, password_blob: bytes, notes: str = ""):
        now = datetime.datetime.utcnow().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE entries SET site=?, username=?, password_blob=?, notes=?, updated_at=? WHERE id=?",
            (site, username, password_blob, notes, now, entry_id),
        )
        self.conn.commit()

    def delete_entry(self, entry_id: int):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self.conn.commit()

    def list_entries(self) -> List[Tuple[int, str, str, bytes, str]]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, site, username, password_blob, notes FROM entries ORDER BY site COLLATE NOCASE")
        return cur.fetchall()

    def search_entries(self, query: str) -> List[Tuple[int, str, str, bytes, str]]:
        like = f"%{query}%"
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, site, username, password_blob, notes FROM entries WHERE site LIKE ? OR username LIKE ? OR notes LIKE ? ORDER BY site COLLATE NOCASE",
            (like, like, like),
        )
        return cur.fetchall()

    def get_entry(self, entry_id: int) -> Optional[Tuple[int, str, str, bytes, str]]:
        cur = self.conn.cursor()
        cur.execute("SELECT id, site, username, password_blob, notes FROM entries WHERE id=?", (entry_id,))
        return cur.fetchone()

    def close(self):
        self.conn.close()


class PasswordGenerator:
    @staticmethod
    def generate(length: int = 16, use_symbols: bool = True) -> str:
        if length < 4:
            raise ValueError("Minimum length is 4")
        alphabet = string.ascii_letters + string.digits
        if use_symbols:
            alphabet += string.punctuation
        # Use secrets.choice for cryptographically secure randomness
        return ''.join(secrets.choice(alphabet) for _ in range(length))


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.db = DatabaseManager()
        self.crypto: Optional[CryptoManager] = None
        self._build_ui()
        # Attempt to unlock (create master on first run)
        self._ensure_master_and_unlock()
        if self.crypto:
            self._refresh_list()

    def _build_ui(self):
        frame = tk.Frame(self.root, padx=8, pady=8)
        frame.pack(fill=tk.BOTH, expand=True)

        top = tk.Frame(frame)
        top.pack(fill=tk.X)

        tk.Label(top, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind('<Return>', lambda e: self._on_search())

        tk.Button(top, text="Search", command=self._on_search).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Clear", command=self._on_clear_search).pack(side=tk.LEFT)

        mid = tk.Frame(frame)
        mid.pack(fill=tk.BOTH, expand=True, pady=8)

        self.listbox = tk.Listbox(mid)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.listbox.bind('<<ListboxSelect>>', lambda e: self._on_select())

        scrollbar = tk.Scrollbar(mid, command=self.listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)

        right = tk.Frame(frame)
        right.pack(fill=tk.X)

        btn_frame = tk.Frame(right)
        btn_frame.pack(fill=tk.X)

        tk.Button(btn_frame, text="Add", width=10, command=self._on_add).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Edit", width=10, command=self._on_edit).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Delete", width=10, command=self._on_delete).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="Export Backup", width=12, command=self._on_export).pack(side=tk.LEFT, padx=4)

        self.details_text = tk.Text(frame, height=6)
        self.details_text.pack(fill=tk.X)
        self.details_text.config(state=tk.DISABLED)

    def _ensure_master_and_unlock(self):
        salt = self.db.get_meta('salt')
        verifier = self.db.get_meta('verifier')
        if salt is None or verifier is None:
            # First run -- create master
            messagebox.showinfo("Welcome", "No master password found. Create a new master password.")
            while True:
                pwd1 = simpledialog.askstring("Set Master Password", "Enter new master password:", show='*')
                if pwd1 is None:
                    sys.exit(0)
                if len(pwd1) < 8:
                    messagebox.showwarning("Weak", "Use at least 8 characters for the master password.")
                    continue
                pwd2 = simpledialog.askstring("Confirm", "Re-enter master password:", show='*')
                if pwd1 != pwd2:
                    messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
                    continue
                # create salt and store verifier
                salt = secrets.token_bytes(16)
                cm = CryptoManager(pwd1, salt)
                token = cm.encrypt(VERIFIER_PLAINTEXT.decode('utf-8'))
                self.db.set_meta('salt', salt)
                self.db.set_meta('verifier', token)
                messagebox.showinfo("Done", "Master password created. Remember it—if you forget it, data cannot be recovered.")
                self.crypto = cm
                break
        else:
            # Prompt for master password and try to derive key
            attempts = 0
            while attempts < 5:
                pwd = simpledialog.askstring("Master Password", "Enter master password:", show='*')
                if pwd is None:
                    sys.exit(0)
                cm = CryptoManager(pwd, salt)
                try:
                    decrypted = cm.decrypt(verifier)
                    if decrypted.encode('utf-8') == VERIFIER_PLAINTEXT:
                        self.crypto = cm
                        return
                    else:
                        raise ValueError
                except Exception:
                    attempts += 1
                    messagebox.showerror("Wrong", f"Master password incorrect ({attempts}/5)")
            messagebox.showerror("Locked", "Too many failed attempts. Exiting.")
            sys.exit(1)

    def _refresh_list(self, items: Optional[List[Tuple]] = None):
        self.listbox.delete(0, tk.END)
        if items is None:
            rows = self.db.list_entries()
        else:
            rows = items
        self._cached_rows = rows
        for r in rows:
            _id, site, username, _, notes = r
            display = f"{site} — {username} (#{_id})"
            self.listbox.insert(tk.END, display)
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete('1.0', tk.END)
        self.details_text.config(state=tk.DISABLED)

    def _on_search(self):
        q = self.search_var.get().strip()
        if not q:
            self._refresh_list()
            return
        rows = self.db.search_entries(q)
        self._refresh_list(rows)

    def _on_clear_search(self):
        self.search_var.set('')
        self._refresh_list()

    def _on_select(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        row = self._cached_rows[idx]
        entry_id, site, username, password_blob, notes = row
        try:
            password = self.crypto.decrypt(password_blob)
        except Exception as e:
            password = f"<error decrypting: {e}>"
        txt = f"Site: {site}\nUsername: {username}\nPassword: {password}\nNotes: {notes}\n"
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete('1.0', tk.END)
        self.details_text.insert(tk.END, txt)
        self.details_text.config(state=tk.DISABLED)

    def _on_add(self):
        dlg = EntryDialog(self.root, title="Add Entry")
        if not dlg.result:
            return
        site, username, password, notes = dlg.result
        # Validation
        if not site.strip() or not username.strip() or not password:
            messagebox.showerror("Invalid", "Site, username and password cannot be empty")
            return
        try:
            blob = self.crypto.encrypt(password)
            self.db.add_entry(site.strip(), username.strip(), blob, notes.strip())
            self._refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add entry: {e}")

    def _on_edit(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select an entry to edit")
            return
        idx = sel[0]
        row = self._cached_rows[idx]
        entry_id, site, username, password_blob, notes = row
        try:
            password = self.crypto.decrypt(password_blob)
        except Exception as e:
            messagebox.showerror("Decrypt", f"Cannot decrypt existing password: {e}")
            return
        dlg = EntryDialog(self.root, title="Edit Entry", site=site, username=username, password=password, notes=notes)
        if not dlg.result:
            return
        nsite, nuser, npass, nnotes = dlg.result
        if not nsite.strip() or not nuser.strip() or not npass:
            messagebox.showerror("Invalid", "Site, username and password cannot be empty")
            return
        try:
            blob = self.crypto.encrypt(npass)
            self.db.update_entry(entry_id, nsite.strip(), nuser.strip(), blob, nnotes.strip())
            self._refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update: {e}")

    def _on_delete(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select an entry to delete")
            return
        idx = sel[0]
        row = self._cached_rows[idx]
        entry_id, site, username, _, _ = row
        if not messagebox.askyesno("Confirm", f"Delete entry for {site} / {username}?"):
            return
        try:
            self.db.delete_entry(entry_id)
            self._refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete: {e}")

    def _on_export(self):
        # Export decrypted entries to JSON and encrypt the export with current key
        rows = self.db.list_entries()
        export_list = []
        for row in rows:
            _id, site, username, password_blob, notes = row
            try:
                password = self.crypto.decrypt(password_blob)
            except Exception:
                password = None
            export_list.append({
                'id': _id,
                'site': site,
                'username': username,
                'password': password,
                'notes': notes,
            })
        payload = json.dumps({'exported_at': datetime.datetime.utcnow().isoformat(), 'entries': export_list}, indent=2)
        token = self.crypto.encrypt(payload)
        fpath = filedialog.asksaveasfilename(defaultextension='.vault', filetypes=[('Vault backup', '*.vault'), ('All files', '*.*')])
        if not fpath:
            return
        try:
            with open(fpath, 'wb') as f:
                f.write(token)
            messagebox.showinfo('Exported', f'Encrypted backup saved to {fpath}')
        except Exception as e:
            messagebox.showerror('Error', f'Failed to write backup: {e}')

    def close(self):
        self.db.close()


class EntryDialog(simpledialog.Dialog):
    def __init__(self, parent, title=None, site='', username='', password='', notes=''):
        self.initial_site = site
        self.initial_username = username
        self.initial_password = password
        self.initial_notes = notes
        self.result = None
        super().__init__(parent, title=title)

    def body(self, master):
        tk.Label(master, text="Site:").grid(row=0)
        tk.Label(master, text="Username:").grid(row=1)
        tk.Label(master, text="Password:").grid(row=2)
        tk.Label(master, text="Notes:").grid(row=3)

        self.site_e = tk.Entry(master)
        self.user_e = tk.Entry(master)
        self.pwd_e = tk.Entry(master, show='*')
        self.notes_e = tk.Text(master, height=4, width=40)

        self.site_e.grid(row=0, column=1)
        self.user_e.grid(row=1, column=1)
        self.pwd_e.grid(row=2, column=1)
        self.notes_e.grid(row=3, column=1)

        self.site_e.insert(0, self.initial_site)
        self.user_e.insert(0, self.initial_username)
        self.pwd_e.insert(0, self.initial_password)
        self.notes_e.insert('1.0', self.initial_notes)

        btn = tk.Button(master, text="Generate", command=self._on_generate)
        btn.grid(row=2, column=2, padx=4)
        return self.site_e

    def _on_generate(self):
        try:
            length = simpledialog.askinteger('Length', 'Password length', initialvalue=16, minvalue=4, maxvalue=256)
            if length is None:
                return
            pwd = PasswordGenerator.generate(length=length)
            self.pwd_e.delete(0, tk.END)
            self.pwd_e.insert(0, pwd)
        except Exception as e:
            messagebox.showerror('Error', f'Password generation failed: {e}')

    def apply(self):
        site = self.site_e.get()
        user = self.user_e.get()
        pwd = self.pwd_e.get()
        notes = self.notes_e.get('1.0', tk.END).strip()
        self.result = (site, user, pwd, notes)


def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    try:
        root.protocol("WM_DELETE_WINDOW", lambda: (app.close(), root.destroy()))
        root.mainloop()
    except KeyboardInterrupt:
        app.close()


if __name__ == '__main__':
    main()
