from .crypto import new_fernet_key

if __name__ == "__main__":
    print("ESCROW_FERNET_KEY=" + new_fernet_key())
