# vulnerability_scanner.py
import os
import json
import socket

def scan_system():
    # Scan system for open ports
    open_ports = []
    for port in range(1, 1024):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("localhost", port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    # Check for outdated software
    outdated_software = []
    software_list = ["apache", "mysql", "php"]
    for software in software_list:
        version = get_software_version(software)
        if version < get_latest_version(software):
            outdated_software.append(software)

    # Check for weak passwords
    weak_passwords = []
    password_list = ["root", "admin", "password"]
    for password in password_list:
        if check_password_strength(password) < 8:
            weak_passwords.append(password)

    # Return a dictionary of vulnerabilities
    vulnerabilities = {
        "open_ports": open_ports,
        "outdated_software": outdated_software,
        "weak_passwords": weak_passwords
    }
    return vulnerabilities

def main():
    config = json.load(open("config.json"))
    vulnerabilities = scan_system()
    print("Vulnerabilities:")
    for key, value in vulnerabilities.items():
        print(f"{key}: {value}")

if __name__ == "__main__":
    main()
