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
