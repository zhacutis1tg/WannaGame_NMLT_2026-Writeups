## Challenge: Try to crack
### Information
<img width="1120" height="330" alt="0" src="https://github.com/user-attachments/assets/5648dc3b-bb1b-4862-b2fa-30ed4a56955e" />

### Solution
Given the hint "Steg challenge", we suspect the flag is hidden within the provided image.  
#### Step 1: Check for embedded content
First, we attempt to extract hidden data using `steghide`.
Command:
```bash
steghide extract -sf chall.jpg
```
  
<img width="606" height="101" alt="image" src="https://github.com/user-attachments/assets/73270d3a-53b9-42f1-a246-7d1c6c8080e7" />  

  
The extraction failed because it requires a passphrase, which is currently unknown.  
#### Step 2: Brute-force the passphrase
We can attempt to crack the passphrase using the `rockyou.txt` wordlist.

If `rockyou.txt` is not available locally, download it using:
```bash
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
``` 

Next, use `stegseek` to brute-force the passphrase against the wordlist:  
```bash
stegseek chall.jpg rockyou.txt
```
  
<img width="623" height="155" alt="image" src="https://github.com/user-attachments/assets/6d7f3d53-5c2b-4a61-a84f-db4366ce3118" />

#### Step 3: Extract and analyze
Upon finding the correct passphrase, stegseek automatically extracts a file named `somethingforyou.zip`. Unzipping this archive reveals two files:
- `part1.txt`: Contains the first part of the flag.  
- `secret.png`: Suspected to contain the second part.  
  
Finally, we analyze secret.png using zsteg to reveal the remaining hidden data:  
```bash
zsteg secret.png
```  
<img width="771" height="112" alt="image" src="https://github.com/user-attachments/assets/f9e16684-6b0d-4d84-975d-b17da457aec1" />
