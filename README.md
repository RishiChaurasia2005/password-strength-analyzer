# Password Strength Analyzer

## Project Overview

**Password Strength Analyzer** is a completed internship project for the **Thiranex Student Program** in the cybersecurity domain. The tool evaluates user-entered passwords based on **length, complexity, and uniqueness**, estimates **entropy** and **password crack time**, and provides **cryptographically secure password suggestions**.

---

## Key Features

- ✅ Length Check
- ✅ Complexity Check
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters
- ✅ Uniqueness Check against a local common-password list
- ✅ Entropy Calculation and crack time estimation
- ✅ Dynamic scoring and entropy-based strength classification
- ✅ Secure password suggestions generated using Python's `secrets` module
- ✅ Command Line Interface (CLI)
- ✅ Tkinter-based Graphical User Interface (GUI)
- ✅ Placeholder for HaveIBeenPwned breach-check integration

---

## Repository Structure

```text
Password-Strength-Analyzer/
│
├── analyzer.py              # Core analysis logic, entropy, scoring, suggestions
├── app.py                   # CLI and Tkinter GUI integration
├── common_passwords.txt     # Common passwords used for uniqueness checks
└── README.md                # Project documentation
```

---

## Requirements

- Python 3.8 or later
- Standard Python library only (no external packages required)
- Optional internet connection for future breach-check integration

---

## Setup

1. Clone or download this repository.
2. Place the following files in the same directory:
   - `analyzer.py`
   - `app.py`
   - `common_passwords.txt`
3. Ensure Python 3 is installed and available in your system PATH.

---

## Usage

### Analyze a Password (CLI)

```bash
python app.py -p "MyPass@123"
```

### Generate Suggested Passwords

```bash
python app.py -p "weakpass" --suggest
```

### Launch the GUI

```bash
python app.py --gui
```

---

## GUI Usage

1. Enter a password in the input field.
2. Click **Analyze** to view:
   - Password strength
   - Entropy
   - Estimated crack time
   - Security tips
   - Password suggestions
3. Click **Generate Strong Password** to create a secure password and analyze it automatically.
4. Use **Copy Top Suggestion** to copy the generated password to the clipboard.

---

## Security Notes

- Passwords are generated using Python's **`secrets`** module for cryptographic randomness.
- Never store generated passwords in plaintext.
- Use a trusted password manager for secure storage.
- The breach-check feature is currently a placeholder.
- Integrate the **HaveIBeenPwned k-Anonymity API** or another trusted breached-password database for production use.
- Clear your clipboard after copying sensitive passwords if required by your organization's security policy.

---

## Future Improvements

- Integrate HaveIBeenPwned API for real-world breach detection.
- Replace `common_passwords.txt` with a larger, regularly updated password dataset.
- Add server-side password history checks to prevent password reuse.
- Implement unit testing.
- Add GitHub Actions for automated testing and continuous integration (CI).
- Export password analysis reports.

---

## Attribution

This project was completed as part of the **Thiranex Student Program** in the **Cybersecurity** domain.

For more information, visit:

**https://www.thiranex.in/student**

---

## License

This project does not currently include a license.

- BSD 3-Clause License

Add the corresponding `LICENSE` file to the repository before distribution.
