# EUTechFourthProject
Password Vault


- **OOP design** with clear separation of responsibilities:
  - `CryptoManager` – handles encryption/decryption with PBKDF2HMAC + Fernet
  - `DatabaseManager` – manages SQLite database (`vault.db`)
  - `PasswordGenerator` – creates strong random passwords
  - `PasswordManagerGUI` – Tkinter-based graphical interface
- Secure storage:
  - All entries encrypted with your master password
  - Salted key derivation (`PBKDF2HMAC`)
- CRUD operations:
  - Add / Edit / Delete / Search / List / View (decrypt) entries
- Password generator
- Encrypted export/backup (`.vault` file)

bash
pip install cryptography
python PasswordVault.py

On the first run:
You’ll be prompted to set a master password
A vault.db database file will be created in the same folder

Backup & Restore

Export your vault to an encrypted .vault file via the GUI
Keep backups safe — they are still encrypted with your master password

Main application window
![screen1](screen1.jpg)
![screen2](screen2.jpg)
![screen3](screen3.jpg)
![screen4](screen4.jpg)
![screen5](screen5.jpg)
![screen6](screen6.jpg)
![screen7](screen7.jpg)
![screen8](screen8.jpg)

Adding/editing an entry

Viewing decrypted entry details

Password generator dialog

Export/backup dialog


If you forget your master password, data cannot be recovered

