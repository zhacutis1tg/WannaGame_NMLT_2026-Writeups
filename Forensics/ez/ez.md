# Challenge: ez
## Information
<img width="1074" height="281" alt="image" src="https://github.com/user-attachments/assets/ff2e8172-f5b6-4b84-977c-37583a2b98ad" />

## Solution
The challenge begins with a compressed file named `chall.tar.gz`. After extracting the archive, we navigate through the directory structure `home/mizuchi/` to find a single image file named `image.jpg`.  

Trying to use common analystic tools such as `strings`, `binwalk`, `exiftool`, we don't receive any useful information.  

Since the file itself seems "clean", we must look for traces left by the user who created the challenge. By listing all hidden files with `ls -la`, we discover a highly suspicious file `.python_history`. 

This file records every command entered into the Python interactive shell. Upon inspection, we find the following script snippet:
```python
from arc4 import ARC4
import os
key = os.getenv('EASY')
key = bytes.fromhex(key)
c = ARC4(key)
enc = bytes.fromhex('506635d2b6b15aefd93f4c6559c97fd5790cdd91ed5a7f4dea0e137381a00a5a2108')
c.decrypt(enc)
```

We now need to find where the `EASY` variable was defined. We search through system configuration files like `.bashrc`, `.profile`, or `.bash_history`.
```bash
grep -a "EASY" .bashrc .profile .bash_history 2>/dev/null
```
  
<img width="812" height="74" alt="image" src="https://github.com/user-attachments/assets/b7f8e0ec-0fda-47d9-a612-e0be3177468d" />

We can see that the key is not a simple string. It is the SHA256 hash of the `image.jpg` file.  

Run the hash command on the image:
```bash
sha256sum image.jpg
```

<img width="784" height="53" alt="image" src="https://github.com/user-attachments/assets/a5e497cb-ef3d-47da-94fe-f11ceb1f199e" />

Finally, using a pure Python implementation of the RC4 algorithm (to avoid library dependencies), we can recover the Flag.
```python
def rc4_decrypt(key, data):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

key = bytes.fromhex("9446ac9ccc7314c94a0db450101da7eea99ada04f1287f527512c5f2115c88c1")
ciphertext = bytes.fromhex("506635d2b6b15aefd93f4c6559c97fd5790cdd91ed5a7f4dea0e137381a00a5a2108")

result = rc4_decrypt(key, ciphertext)
print("Flag:", result.decode())
```

<img width="784" height="53" alt="image" src="https://github.com/user-attachments/assets/f2e9ccb9-9799-4951-8112-51ba6f0daa53" />
