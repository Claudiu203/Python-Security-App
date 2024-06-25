import warnings
warnings.filterwarnings('ignore')
import os
import tkinter as tk
import spwd
import time
import pwd
import grp
import subprocess



suspiciousProcesses = []
setuidFiles = []
Vulnerabilities = []
security_updates = []
file_permision = []
empty_password = []
root_users = []
disabled_accounts = []
ssh_problems = []
sens_group_mem = []
files_to_check = {
    "/etc/passwd": "644",
    "/etc/shadow": "600",
    "/etc/group": "644",
    "/etc/gshadow": "600",
    "/etc/sudoers": "440",
    "/boot": "755",
    "/usr/bin": "755",
    "/usr/sbin": "755",
    "/var/log": "755",
    "/etc/hostname": "644",
    "/etc/hosts": "644",
    "/etc/fstab": "644",
}

def check_file_permissions(file_path, expected_permissions):
    actual_permissions = oct(os.stat(file_path).st_mode)[-3:]
    if actual_permissions != expected_permissions:
        file_permision.append(f"Warning: {file_path} permissions are {actual_permissions}, expected {expected_permissions}")

def check_permissions():
    print("Checking for file permisions...")
    for file, permissions in files_to_check.items():
        check_file_permissions(file, permissions)

def check_security_updates():
    print("Checking for security updates ...")
    updates = []
    subprocess.run(['sudo', 'apt-get', 'update'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = subprocess.run(['apt-get', 'upgrade', '-s'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    for line in output.split('\n'):
        if 'security' in line.lower():
            updates.append(line)
    return updates

def get_securityUpdates():
    print("Checking for security updates....")
    os.system("sudo apt-get update")
    os.system("sudo apt-get upgrade -s | grep -i security")

def check_users_and_groups():
    print("Checking for user and group vulnerabilities...")
    issues = []
    result = subprocess.run(['sudo', 'getent', 'shadow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode().strip().split('\n')
    
    for line in output:
        parts = line.split(':')
        username = parts[0]
        password = parts[1]

        try:
            user_info = pwd.getpwnam(username)
            if user_info.pw_uid < 1000:
                continue
        except KeyError:
            continue

        if password == '':
            empty_password.append(username)
            issues.append(f"User {username} has an empty password.")
        elif password == '!':
            disabled_accounts.append(username)
            issues.append(f"User {username} account is disabled.")

    root_users_temp = [user.pw_name for user in pwd.getpwall() if user.pw_uid == 0]
    if root_users_temp:
        root_users = root_users_temp
        issues.append(f"Root users: {', '.join(root_users)}")

    # Identify users in sensitive groups
    sensitive_groups = ['sudo', 'wheel']
    for group_name in sensitive_groups:
        try:
            group_info = grp.getgrnam(group_name)
            if group_info.gr_mem:
                sens_group_mem = group_info.gr_mem
                issues.append(f"Users in {group_name} group: {', '.join(group_info.gr_mem)}")
        except KeyError:
            continue

    # Check for duplicate usernames and UIDs
    usernames = [user.pw_name for user in pwd.getpwall()]
    uids = [user.pw_uid for user in pwd.getpwall()]
    if len(usernames) != len(set(usernames)):
        issues.append("Duplicate usernames found.")
    if len(uids) != len(set(uids)):
        issues.append("Duplicate UIDs found.")

    # Check password expiry
    for user in pwd.getpwall():
        result = subprocess.run(['sudo', 'chage', '-l', user.pw_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode().strip().split('\n')
        for line in output:
            if 'Password expires' in line and 'never' not in line:
                parts = line.split(': ')
                expiry_date = parts[1].strip()
                if expiry_date and expiry_date != 'never':
                    issues.append(f"User {user.pw_name} password expires on {expiry_date}.")

    return issues 

def check_suspicious_processes():
    print("Checking for suspicious processes...")
    result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    suspicious_processes = ["nc", "netcat", "ncat", "perl", "python", "php", "ruby"]
    for line in output.split('\n'):
        for process in suspicious_processes:
            if process in line:
                suspiciousProcesses.append(line)
                break

def check_ssh_configuration():
    sshd_config = "/etc/ssh/sshd_config"
    print("Checking SSH configuration...")
    if os.path.exists(sshd_config):
        with open(sshd_config, 'r') as file:
            config = file.read()
            if "PermitRootLogin no" not in config:
                ssh_problems.append("Warning: PermitRootLogin should be set to 'no'")
            if "PasswordAuthentication no" not in config:
                ssh_problems.append("Warning: PasswordAuthentication should be set to 'no'")
    else:
        print("sshd_config file does not exist.")


def check_open_ports():
    print("Checking for open ports...")
    try:
        result = subprocess.run(['sudo', 'ss', '-tuln'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error executing ss command: {result.stderr.strip()}")

        lines = result.stdout.strip().split('\n')
        headers = lines[0]
        open_ports = lines[1:]

        if not open_ports:
            return ["No open ports found."]
        
        issues = ["Open ports detected:"]
        for line in open_ports:
            issues.append(line)

        return issues

    except Exception as e:
        return [f"An error occurred: {str(e)}"]

def check_setuid_files():
    print("Checking for setuid files...")
    result = subprocess.run(['find', '/', '-perm', '/4000'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    for line in output.split("\n"):
        if "denied" not in line:
            setuidFiles.append(line)

def check_system_logs():
    print("Checking system logs for suspicious activity...")
    os.system("grep -i 'failed password' /var/log/auth.log")
    os.system("grep -i 'segfault' /var/log/syslog")

def check_CVE_2016_5195():
    result = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    if output[0] < "7":
        print("Sistem linux trebuie actualizat. Esti vulnerabil la CVE_2016_5195. Pentru mai multe detalii intrati pe urmatorul link: https://nvd.nist.gov/vuln/detail/CVE-2016-5195")

def check_firewall_status():
    print("Checking firewall status...")
    try:
        result = subprocess.run(['sudo', 'ufw', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error executing ufw command: {result.stderr.strip()}")

        status_output = result.stdout.strip()
        if "Status: inactive" in status_output:
            return ["Firewall status: Inactive"]
        elif "Status: active" in status_output:
            return ["Firewall status: Active", status_output]
        else:
            return ["Firewall status: Unknown", status_output]

    except Exception as e:
        return [f"An error occurred: {str(e)}"]

def check_chkrootkit():
    print("Checking rootkit for problems...")
    try:
        result = subprocess.run(['sudo', 'chkrootkit'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error executing chkrootkit command: {result.stderr.strip()}")

        output = result.stdout.strip().split('\n')
        issues = []

        for line in output:
            if 'INFECTED' in line or 'Vulnerable' in line:
                issues.append(line)

        if not issues:
            return ["chkrootkit: No issues found"]
        else:
            return ["chkrootkit: Potential issues detected"] + issues

    except Exception as e:
        return [f"An error occurred: {str(e)}"]



def menu():
    print("Python Security Script")
    print(os.getcwd())
    check_security_updates()
    check_permissions()
    time.sleep(5)
    check_ssh_configuration()
    time.sleep(5)
    issues = check_users_and_groups()
    time.sleep(5)
    ports = check_open_ports()
    time.sleep(5)
    firewall = check_firewall_status()
    time.sleep(5)
    rootkit = check_chkrootkit()
    time.sleep(5)

    print("\n\n\n")

    print("Problemele gasite sunt urmatoarele:")
    if security_updates != []:
        print("Aceste actualizari de securitate sunt disponibile")
        for line in security_updates:
            print(line)
    if file_permision != []:
        for line in file_permision:
            print(line)
    for line in issues:
        print(line)
    if ssh_problems != []:
        for line in ssh_problems:
            print(line)
    if ports != []:
        for line in ports:
            print(line)
    print(firewall[0])
    print(rootkit[0])

    


menu()

#check_suspicious_processes()
#check_setuid_files()
#check_system_logs()
#check_CVE_2016_5195()