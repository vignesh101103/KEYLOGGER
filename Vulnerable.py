import os
import json
import socket
import subprocess

def get_software_version(software):
    try:
        # Use the `subprocess` module to run a command to get the software version
        # For example, to get the Apache version, you can use the command "apache2 -v"
        # Replace "apache2 -v" with the appropriate command for the software
        output = subprocess.check_output([software, "-v"])
        # Parse the output to extract the version number
        version = output.decode("utf-8").splitlines()[0].split()[2]
        return version
    except subprocess.CalledProcessError:
        # If the command fails, return a default value or handle the error
        return "Unknown"

def check_password_strength(password):
    strength = 0
    if len(password) < 8:
        return strength
    if re.search("[a-z]", password):
        strength += 1
    if re.search("[A-Z]", password):
        strength += 1
    if re.search("[0-9]", password):
        strength += 1
    if re.search("[!@#$%^&*()_+=-{};:'<>,./?]", password):
        strength += 1
    return strength

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
    if not vulnerabilities:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()
