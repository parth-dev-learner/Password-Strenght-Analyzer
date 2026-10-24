# PassGuard — Password Strength Analyzer 🛡️

A cybersecurity web application that helps you understand just how strong (or weak) your passwords really are. Built with Python and Flask on the backend, with a clean dark-themed frontend that gives you real-time feedback as you type.

---

## What This Project Does

Most people either use weak passwords they can remember, or they pick something that *looks* complex but follows a predictable pattern an attacker would crack in seconds. This tool helps bridge that gap — it shows you exactly why a password is weak, how long it would take to crack, and what you can do to fix it.

It's not just a bar that goes from red to green. You get actual numbers: entropy in bits, character-set size, estimated combinations, and crack times ranging from a casual online attack all the way up to a supercomputer cluster. Plus it flags patterns like keyboard walks (`qwerty`), leet-speak tricks (`p@ssw0rd`), repeated characters, and year patterns that attackers check first.

---

## Features

### Real-time Password Analysis
- **Strength Score (0–100):** Weighted scoring across length, character diversity, entropy, and detected patterns
- **Shannon Entropy:** Measures the randomness of your password in bits — higher is better
- **Charset Size:** How many unique characters are in your password's possible alphabet
- **Combination Count:** The total number of passwords with the same length and charset (shown in scientific notation)

### Crack Time Estimation
Estimates how long a brute-force attack would take across five different threat models:
- Online attack (throttled, ~1,000/sec)
- Fast online attack (~10,000/sec)
- Offline hash crack (~1 million/sec)
- GPU cluster (~1 billion/sec)
- Supercomputer / nation-state level (~1 trillion/sec)

### Pattern Detection
The backend checks for things that attackers specifically look for:
- Repeated characters (`aaaa`, `1111`)
- Sequential patterns (`abc`, `123`)
- Keyboard row walks (`qwerty`, `asdf`)
- Leet-speak substitutions (`p@ssw0rd` → detected as `password`)
- Year patterns (`1998`, `2024`)
- Weak common suffixes (`123`, `!`)
- Purely numeric or purely alphabetic passwords

### HIBP K-Anonymity Integration
The app computes the first 5 characters of your password's SHA-1 hash locally — your actual password is never sent anywhere. You can take that prefix and query `api.pwnedpasswords.com/range/{prefix}` yourself to check whether your password has appeared in known data breaches, without exposing it.

### Password Generator
Generate cryptographically strong passwords using Python's `secrets` module (not `random`):
- **Mixed mode:** Picks from the full character set, always includes at least one uppercase, lowercase, digit, and symbol
- **Passphrase mode:** Builds a 4-word passphrase separated by a random symbol (e.g., `tiger-ember-lunar-nova!47`) — long, readable, and very hard to crack
- Adjustable length from 8 to 64 characters

### Password Comparator
Paste up to 5 passwords and compare their scores side by side — useful for deciding between options or showing students the difference between seemingly similar passwords.

### Session History
Keeps a rolling list of the last 10 passwords you analyzed in the current session. Passwords themselves aren't stored — only the SHA-1 prefix, score, and timestamp are kept, so it's safe for classroom demos.

---

## Project Structure

```
pass/
├── app.py              # Flask backend with all analysis logic
├── requirements.txt    # Only needs Flask — everything else is stdlib
├── templates/
│   └── index.html      # Single-page UI (HTML + CSS + vanilla JS)
└── README.md
```

---

## Getting Started

**Prerequisites:** Python 3.8 or newer.

### 1. Clone or download the project

```bash
git clone <your-repo-url>
cd pass
```

### 2. Set up a virtual environment (recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python app.py
```

Then open your browser at **http://localhost:5000**

---

## How the Scoring Works

The score is calculated on a 0–100 scale:

| Factor | Max Points |
|---|---|
| Password length | 30 |
| Character diversity (uppercase, lowercase, digits, symbols) | 24 |
| Shannon entropy | 25 |
| Pattern penalties | −7 per pattern found |
| Common password override | Hard-capped at 5 |

The labels map as:
- 85–100 → **Very Strong**
- 65–84 → **Strong**
- 45–64 → **Moderate**
- 25–44 → **Weak**
- 0–24 → **Very Weak**

---

## Security Notes

- **No passwords are logged or stored.** The Flask backend processes them in memory and returns results immediately.
- The `secrets` module is used for password generation, which uses the OS's cryptographically secure random source — not the `random` module.
- The HIBP check uses k-anonymity: only the 5-character SHA-1 prefix is computed and shown. The actual password hash is never transmitted.
- Session history only stores the SHA-1 prefix, score, label, and length — never the raw password.

---

## Technologies Used

| Layer | Tech |
|---|---|
| Backend | Python 3, Flask |
| Cryptography | `hashlib`, `secrets` (stdlib) |
| Analysis | `re`, `math`, `collections.Counter` (stdlib) |
| Frontend | HTML5, Vanilla CSS, Vanilla JavaScript |
| Fonts | Inter + JetBrains Mono (Google Fonts) |

---

## Cybersecurity Concepts Covered

This project demonstrates several real-world password security concepts:

- **Shannon Entropy** — information-theoretic measure of randomness
- **Brute-force attack modeling** — estimating crack times at different hardware speeds
- **Dictionary and rule-based attacks** — detecting patterns attackers specifically exploit
- **K-anonymity** — how HIBP allows breach checking without exposing your password
- **Cryptographic randomness** — why `secrets` matters vs. `random` for security applications
- **Character set expansion** — why adding symbols matters exponentially (not linearly)

---

## Screenshots

Run the app and visit `http://localhost:5000` — the interface is fully interactive and works best in a modern browser (Chrome, Firefox, Edge).

---

## Author

Made by **Parth** as part of a Cybersecurity course project.

Feel free to fork, extend, or use this as a reference for your own security tools. If you add HIBP live API integration or a zxcvbn comparison, that would be a solid next step.

---

## License

MIT License — use it, modify it, share it. Just don't use it for anything malicious.
