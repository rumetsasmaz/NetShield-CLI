# 🛡️ NetShield-CLI

**NetShield-CLI** is a modular, Python-based cybersecurity command-line toolkit designed for learning, experimentation, and basic security analysis.

The project brings several small security utilities together into a single CLI, making it easier to practice Python programming while exploring fundamental cybersecurity concepts.

> ⚠️ **Educational Project:** NetShield-CLI is primarily developed for learning and authorized security testing. Do not use its features against systems, accounts, or data that you do not own or have explicit permission to test.

---

## ✨ Features

### 🔐 Password Generator

Generate random passwords with customizable parameters.

* Configurable password length
* Random character generation
* Suitable for creating strong test passwords

### 📊 Password Strength Checker

Analyze password complexity and receive feedback about potential weaknesses.

The checker evaluates factors such as:

* Password length
* Uppercase characters
* Lowercase characters
* Numbers
* Special characters
* Overall structural complexity

### 🔑 Hash Generator

Generate cryptographic hashes from text input.

Currently supported:

* MD5
* SHA-256

Useful for learning how hashing works and understanding data integrity concepts.

### 🔓 Hash Cracker

Perform dictionary-based hash matching against MD5 and SHA-256 hashes.

This feature is intended to demonstrate:

* Password hashing concepts
* Dictionary attacks
* Weak password exposure
* Why strong passwords and secure password hashing are important

### 🌐 Port Reference

Quickly look up commonly used network ports and their associated services.

Useful when learning:

* TCP/IP networking
* Common network services
* Well-known ports
* Basic network reconnaissance concepts

---

## 🧰 Technologies

NetShield-CLI is currently built with:

* **Python 3**
* `hashlib`
* `random`
* `colorama`

The project intentionally keeps its dependencies lightweight to make the source code easier to understand and modify.

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/rumetsasmaz/NetShield-CLI.git
cd NetShield-CLI
```

### 2. Install dependencies

```bash
pip install colorama
```

### 3. Run NetShield-CLI

```bash
python main.py
```

---

## 🚀 Usage

After starting the program, use the CLI menu to select the security utility you want to use.

Example workflow:

```text
$ python main.py

╔══════════════════════════════════╗
║          NetShield-CLI           ║
║     Cybersecurity Toolkit        ║
╚══════════════════════════════════╝

[1] Password Generator
[2] Password Strength Checker
[3] Hash Generator
[4] Hash Cracker
[5] Port Reference
[0] Exit
```

Select an option and follow the instructions displayed by the program.

---

## 📚 What I Am Learning With This Project

NetShield-CLI is also a personal learning project.

The main goals are to improve my understanding of:

* Python programming
* Functions and modules
* Command-line interfaces
* Exception handling
* String manipulation
* File handling
* Cryptographic hashing
* Password security
* Dictionary-based attacks
* Basic networking concepts
* Security-oriented programming

As the project evolves, additional security utilities may be added.

---

## 🗺️ Roadmap

Planned improvements include:

* [ ] Improve CLI interface
* [ ] Add argument-based commands
* [ ] Add more hash algorithms
* [ ] Improve password strength analysis
* [ ] Expand the port database
* [ ] Add JSON output
* [ ] Add configuration support
* [ ] Improve error handling
* [ ] Add logging
* [ ] Add automated tests
* [ ] Improve project structure
* [ ] Add more educational security utilities

---

## 🔒 Security & Ethical Use

NetShield-CLI is intended for:

* Personal cybersecurity labs
* CTF environments
* Local testing
* Educational exercises
* Systems you own
* Systems for which you have explicit authorization

Do **not** use this software to gain unauthorized access to accounts, systems, networks, or data.

The author is not responsible for misuse of this software.

---

## 🤝 Contributing

Contributions, suggestions, and improvements are welcome.

If you find a bug or have an idea for a new feature:

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Test your changes
5. Open a Pull Request

For larger changes, opening an issue first is recommended.

---

## 📄 License

This project is currently provided for educational purposes.

A formal open-source license can be added as the project matures.

---

## 👨‍💻 Author

**Rumet Şaşmaz**

GitHub:
https://github.com/rumetsasmaz

---

⭐ If you find this project useful for learning cybersecurity or Python, consider giving it a star.
