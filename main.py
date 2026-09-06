import random
import hashlib
from colorama import Fore, Style, init

# Windows terminalinde renk uyumluluğunu açıyoruz
init(autoreset=True)

# Renk tanımlamaları
BLACK = Fore.BLACK
WHITE = Fore.WHITE
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

# ASCII Banner
BANNER = f"""{CYAN}
 _   _  _____ _____ _____ _   _ _____ _____ _     _____    _____ _     _____ 
| \ | ||  ___|_   _/  ___| | | |_   _|  ___| |   |  _  \  /  __ \ |   |_   _|
|  \| || |__   | | \ `--.| |_| | | | | |__ | |   | | | |  | /  \/ |     | |  
| . ` ||  __|  | |  `--. \  _  | | | |  __|| |   | | | |  | |   | |     | |  
| |\  || |___  | | /\__/ / | | | _| |_| |___| |___| |/ /   | \__/\ |_____| |_ 
\_| \_/\____/  \_/ \____/\_| |_/\___/\____/\_____/___/     \____/\_____/\___/
{RESET}"""

def generate_password():
    upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower_case = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    password = ""
    all_chars = upper_case + lower_case + digits + symbols
    for x in range(0, 12):
        password += random.choice(all_chars)
    print(f"\n{GREEN}[+] Generated Password: {password}{RESET}\n")

def check_ports():
    port_database = {
        21: "FTP - Plain text data transfer (Risky)",
        22: "SSH - Secure Connection",
        80: "HTTP - Standard Web (Without Password)",
        443: "HTTPS - Secure Web",
        3389: "RDP - Remote Desktop Connection (Could Be A Target)"
    }
    
    try:
        target_port = int(input(f"{YELLOW}Enter Port Number: {RESET}"))
        
        if target_port in port_database:
            print(f"{GREEN}[+] Port {target_port}: {port_database[target_port]}{RESET}\n")
        else:
            print(f"{RED}[-] Port {target_port}: Not registered in the database or non-standard service.{RESET}\n")
    except ValueError:
        print(f"{RED}[!] Please enter a valid number.{RESET}\n")



def check_password_strength():
    password = input(f"{YELLOW}Enter A Password: ")
    score = 0
    feedback = []

    if len(password) >= 9:
        score += 1
    else:
        feedback.append(f"{RED}Password Should Be Minimum 8 Character")
    
    if any(char.isupper() for char in password):
        score += 1
    else:
        feedback.append(f"{RED}Add Upper Case")

    if any(char.islower() for char in password):
        score += 1 
    else:
        feedback.append(f"{RED}Add Lower Case")

    if any(char.isdigit() for char in password):
        score += 1
    else:
        feedback.append(f"{RED}Add Digit")

    if any(char.isalnum() for char in password):
        score += 1
    else:
        feedback.append(f"{RED}Add Symbol")

    print(f"\nScore: {score}/5")

    if score == 5:
        print(f"{GREEN}Status: Strong Password")
    elif score >= 3:
        print(f"{YELLOW}Status: Medium Password")
    else:
        print(f"{RED}Status: Weak Password")

    if feedback:
        print("\nSuggestion To Improve: ")
        for item in feedback:
            print(f"={item}")


def generate_hash():

    text = input(f"{YELLOW}Enter Password To Hash: ")


    md5_hash = hashlib.md5(text.encode()).hexdigest()

    sha256_hash = hashlib.sha256(text.encode()).hexdigest()

    print(f"{GREEN}\n[+] Original Text: {text}")
    print(f"{GREEN}\n[+] MD5: {md5_hash} ")
    print(f"{GREEN}\n[+] SHA256: {sha256_hash}")


def hash_cracker():

    wordlist = ["123456", "password", "admin", "helloworld", "letmein", "qwerty" , "fuckoff"]

    target_hash = input(f"{YELLOW}Enter A Target Hash: ").strip().lower()
    found = False

    print(f"{RED}\n[+] Starting The Attack...")

    for word in wordlist:

        word_md5 = hashlib.md5(word.encode()).hexdigest()
        word_sha256 = hashlib.sha256(word.encode()).hexdigest()

        if target_hash == word_md5 or target_hash == word_sha256:
            print(f"{GREEN}\n[SUCCESS] Hash Cracked! The Password Is: {word}")
            found = True
            break

    if not found:
        print(f"\n[FAILED]{RED} Password Couldnt Found In The Wordlist")


# Ana Döngü
print(BANNER)

while True:
    print(f"{CYAN}--- NetShield-CLI ---{RESET}")
    print(f"{GREEN}1. Generate Password{RESET}")
    print(f"{GREEN}2. Check Port{RESET}")
    print(f"{GREEN}3. Check Password Strength{RESET}")
    print(f"{GREEN}4. Hash Your Password{RESET}")
    print(f"{GREEN}5. Crack Hash{RESET}")
    print(f"{RED}6. Exit{RESET}")
    
    choice = input(f"\n{YELLOW}Select an option (1-6): {RESET}")

    if choice == "1":
        generate_password()
    elif choice == "2":
        check_ports()
    elif choice == "3":
        check_password_strength()
    elif choice == "4":
        generate_hash()
    elif choice == "5":
        hash_cracker()
    elif choice == "6":
        print(f"\n{RED}Exiting... Goodbye!{RESET}")
        break
    else:
        print(f"\n{RED}[!] Invalid choice, try again.{RESET}\n")