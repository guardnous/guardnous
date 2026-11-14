"""Print the bcrypt hash of a password typed at the prompt (it is not echoed).

Used to reset an account by hand: put the hash in users.hashed_password.
"""
from getpass import getpass

from passlib.context import CryptContext

password = getpass("New password: ")
if len(password) < 12:
    raise SystemExit("Use at least 12 characters.")
print("HASH:" + CryptContext(schemes=["bcrypt"], deprecated="auto").hash(password))
