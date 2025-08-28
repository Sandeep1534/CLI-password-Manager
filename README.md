# CLI-password-Manager
Develop a secure command-line password manager that stores and retrieves  credentials using AES-256 encryption. The application will feature a master password  system, JSON-based storage, and CRUD operations for managing credentials (websites,  usernames, passwords). All sensitive data remains encrypted at rest.
#!/usr/bin/env python3
"""


import os, json, base64, argparse, sys
from getpass import getpass
from typing import Tuple, Dict, Any


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE_DEFAULT = "vault.dat"
KDF_ITERATIONS_DEFAULT = 200_000
SALT_SIZE = 16       # bytes
NONCE_SIZE = 12      # bytes (recommended for AESGCM)
KEY_SIZE = 32        # 32 bytes => AES-256



def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS_DEFAULT) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))



def encrypt_db(db: Dict[str, Any], key: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(db, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_db(ciphertext: bytes, nonce: bytes, key: bytes) -> Dict[str, Any]:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))



def save_vault(path: str, db: Dict[str, Any], key: bytes, salt: bytes, iterations: int) -> None:
    nonce, ciphertext = encrypt_db(db, key)
    package = {
        "kdf": {"salt": b64e(salt), "iterations": iterations},
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "version": 1,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(package, f, ensure_ascii=False, indent=2)


def load_vault(path: str, master_password: str) -> Tuple[Dict[str, Any], bytes, bytes, int]:
    with open(path, "r", encoding="utf-8") as f:
        package = json.load(f)
    salt = b64d(package["kdf"]["salt"])
    iterations = int(package["kdf"]["iterations"])
    nonce = b64d(package["nonce"])
    ciphertext = b64d(package["ciphertext"])
    key = derive_key(master_password, salt, iterations)
    db = decrypt_db(ciphertext, nonce, key)
    return db, key, salt, iterations


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))



def cmd_init(args):
    path = args.vault
    if os.path.exists(path):
        print(f"❌ Vault already exists: {path}")
        sys.exit(1)
    pw1 = getpass("Create master password: ")
    pw2 = getpass("Re-enter master password: ")
    if not pw1 or pw1 != pw2:
        print("❌ Passwords empty or do not match.")
        sys.exit(1)

    salt = os.urandom(SALT_SIZE)
    key = derive_key(pw1, salt)
    db = {}  # { site: { "username": str, "password": str } }
    save_vault(path, db, key, salt, KDF_ITERATIONS_DEFAULT)
    print(f"✅ New vault created at: {path}")


def load_db_with_password_or_exit(path: str) -> Tuple[Dict[str, Any], bytes, bytes, int]:
    if not os.path.exists(path):
        print(f"❌ Vault not found: {path}\n   Run: init --vault {path}")
        sys.exit(1)
    pw = getpass("Master password: ")
    try:
        return load_vault(path, pw)
    except Exception:
        print("❌ Unable to open vault (wrong password or file is corrupt).")
        sys.exit(1)


def cmd_list(args):
    db, *_ = load_db_with_password_or_exit(args.vault)
    if not db:
        print("ℹ️ No entries yet.")
        return
    print("Sites in vault:")
    for site in sorted(db.keys()):
        print(f" - {site}")


def cmd_get(args):
    db, *_ = load_db_with_password_or_exit(args.vault)
    site = args.site
    item = db.get(site)
    if not item:
        print(f"❌ No entry for site: {site}")
        return
    print(f"Site: {site}")
    print(f"Username: {item.get('username','')}")
    print(f"Password: {item.get('password','')}")


def cmd_add(args):
    db, key, salt, iters = load_db_with_password_or_exit(args.vault)
    site = args.site or input("Site: ").strip()
    if not site:
        print("❌ Site is required.")
        return
    if site in db and not args.update:
        print(f"❌ '{site}' already exists. Use 'update' or pass --update to overwrite.")
        return
    username = args.username or input("Username: ").strip()
    password = args.password or getpass("Password (hidden): ")
    db[site] = {"username": username, "password": password}
    save_vault(args.vault, db, key, salt, iters)
    print(f"✅ Saved entry for: {site}")


def cmd_update(args):
    args.update = True
    cmd_add(args)


def cmd_delete(args):
    db, key, salt, iters = load_db_with_password_or_exit(args.vault)
    site = args.site
    if site not in db:
        print(f"❌ No entry for site: {site}")
        return
    confirm = input(f"Delete '{site}'? Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("❎ Cancelled.")
        return
    del db[site]
    save_vault(args.vault, db, key, salt, iters)
    print(f"🗑️ Deleted: {site}")


# ---------- CLI ----------
def build_parser():
    p = argparse.ArgumentParser(
        description="Simple CLI Password Manager (AES-256-GCM, encrypted JSON vault)"
    )
    p.add_argument("--vault", default=VAULT_FILE_DEFAULT, help="Path to vault file (default: vault.dat)")

    sub = p.add_subparsers(dest="command", required=True)

    s_init = sub.add_parser("init", help="Create a new vault")
    s_init.set_defaults(func=cmd_init)

    s_list = sub.add_parser("list", help="List site names")
    s_list.set_defaults(func=cmd_list)

    s_get = sub.add_parser("get", help="Show username/password for a site")
    s_get.add_argument("site", help="Site key (e.g., 'github.com')")
    s_get.set_defaults(func=cmd_get)

    s_add = sub.add_parser("add", help="Add a new credential")
    s_add.add_argument("--site", help="Site key (e.g., 'github.com')")
    s_add.add_argument("--username", help="Username")
    s_add.add_argument("--password", help="Password (omit to be prompted securely)")
    s_add.add_argument("--update", action="store_true", help="Overwrite if site exists")
    s_add.set_defaults(func=cmd_add)

    s_update = sub.add_parser("update", help="Update/overwrite an existing credential")
    s_update.add_argument("site", help="Site key")
    s_update.add_argument("--username", help="New username (omit to keep current or retype)")
    s_update.add_argument("--password", help="New password (omit to be prompted securely)")
    s_update.set_defaults(func=cmd_update)

    s_delete = sub.add_parser("delete", help="Delete a credential")
    s_delete.add_argument("site", help="Site key")
    s_delete.set_defaults(func=cmd_delete)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
