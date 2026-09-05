import random
def generate_password():
    
    upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    lower_case = "abcdefghijklmnopqrstuvwxyz"

    digits = "0123456789"

    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    password = ""

    all_chars = upper_case + lower_case + digits + symbols

    for x in range(0, 12):

        password += random.choice(all_chars)
    print(password)


def check_ports():
    port_database = {

        21: "FTP - Plain text data transfer (Risky)",
        22: "SSH - Secure Connection",
        80: "HTTP - Standard Web (No password)",
        443: "HTTPS - Secure Web",
        3389: "RDP - Remote Desktop Connection (It could be a target.)"
    }


    target_port = int(input("Enter Port Number: "))

    if target_port in port_database:
        print(f"Port {target_port}: {port_database[target_port]}")

    else:
        print(f"Port {target_port}: Not registered in the database or non-standard service.")

while True:
    print("\n--- NetShield-CLI ---")
    print("1. Generate Password")
    print("2. Check Port")
    print("3. Exit")
    
    choice = input("Select an option (1-3): ")

    if choice == "1":
        generate_password()
    elif choice == "2":
        check_ports()
    elif choice == "3":
        print("Exiting...")
        break
    else:
        print("Invalid choice, try again.")