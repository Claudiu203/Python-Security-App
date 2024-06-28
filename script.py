import warnings
warnings.filterwarnings('ignore')
import os
import tkinter as tk
import spwd
import time
import pwd
import grp
import getpass
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
open_ports_global = []
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

    sensitive_groups = ['sudo']
    for group_name in sensitive_groups:
        try:
            group_info = grp.getgrnam(group_name)
            if group_info.gr_mem:
                sens_group_mem = group_info.gr_mem
                issues.append(f"Users in {group_name} group: {', '.join(group_info.gr_mem)}")
        except KeyError:
            continue

    usernames = [user.pw_name for user in pwd.getpwall()]
    uids = [user.pw_uid for user in pwd.getpwall()]
    if len(usernames) != len(set(usernames)):
        issues.append("Duplicate usernames found.")
    if len(uids) != len(set(uids)):
        issues.append("Duplicate UIDs found.")

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
    try:
        suspicious_keywords = [
            " nc ", "netcat", " ncat ", " perl ", "python", "php", "ruby", 
            " nmap ", "telnet", " ssh ", "wget", " curl ", " bash ", " sh ",
            " dd ", " netstat ", " ss ", " tcpdump "
        ]


        result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error executing ps command: {result.stderr.strip()}")

        output = result.stdout.strip().split('\n')
        headers = output[0]
        processes = output[1:]
        
        issues = ["Suspicious processes detected:"]
        suspicious_processes_found = False

        for line in processes:
            for keyword in suspicious_keywords:
                if keyword in line:
                    issues.append(line)
                    suspicious_processes_found = True
                    break  

        if not suspicious_processes_found:
            return ["No suspicious processes found."]
        else:
            return issues

    except Exception as e:
        return [f"An error occurred: {str(e)}"]

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
        for port in open_ports:
            temp = port.split(" ")
            temp2 = temp[17].split(":")
            if(temp2 != ['']):
                open_ports_global.append(temp2[1])
        if not open_ports:
            return ["No open ports found."]
        
        issues = ["Open ports detected:"]
        for line in open_ports:
            issues.append(line)

        return issues

    except Exception as e:
        return [f"An error occurred: {str(e)}"]

def check_setuid_files():
    user = getpass.getuser()
    path = "/home/" + user
    print("Checking for setuid files...")
    result = subprocess.run(['find', path, '-perm', '/4000'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    for line in output.split("\n"):
        if "denied" not in line:
            setuidFiles.append(line)
    setuidFiles.pop()

def check_CVE_2016_5195():
    result = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    if output[0] < "3":
        print("The linux sistem must be updated. You are vulnerable to CVE_2016_5195. For more info click on the following link: https://nvd.nist.gov/vuln/detail/CVE-2016-5195")

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

def change_permissions():
    for file in file_permision:
        temp = file.split(" ")
        subprocess.run(['sudo', 'chmod', files_to_check[temp[1]], temp[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def update_ssh_config():
    sshd_config_path = '/etc/ssh/sshd_config'
    backup_path = '/etc/ssh/sshd_config.bak'

    subprocess.run(['sudo', 'cp', sshd_config_path, backup_path])
    print(f"Backup of sshd_config created at {backup_path}")


    with open(sshd_config_path, 'r') as file:
        lines = file.readlines()

    changes_made = False
    new_lines = []
    for line in lines:
        if line.strip().startswith('PermitRootLogin'):
            new_lines.append('PermitRootLogin no\n')
            changes_made = True
        elif line.strip().startswith('PasswordAuthentication'):
            new_lines.append('PasswordAuthentication no\n')
            changes_made = True
        else:
            new_lines.append(line)

    if not any(line.strip().startswith('PermitRootLogin') for line in new_lines):
        new_lines.append('PermitRootLogin no\n')
        changes_made = True
    if not any(line.strip().startswith('PasswordAuthentication') for line in new_lines):
        new_lines.append('PasswordAuthentication no\n')
        changes_made = True
    
    with open(sshd_config_path, 'w') as file:
        file.writelines(new_lines)
    
    if changes_made:
        print("sshd_config updated with new settings.")
        
        subprocess.run(['sudo', 'systemctl', 'restart', 'sshd'])
        print("SSH service restarted.")
    else:
        print("No changes were made to sshd_config.")

def close_ports(ports):

    for port in ports:
        try:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'udp', '--dport', str(port), '-j', 'DROP'], check=True)
            print(f"Closed port {port}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to close port {port}: {e}")

def activate_firewall():
    """Function to activate ufw firewall."""
    try:
        subprocess.run(['sudo', 'ufw', 'enable'], check=True)
        print("ufw firewall activated.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to activate ufw firewall: {e}")

def remove_setuid_bit():
    for line in setuidFiles:
        subprocess.run(['sudo', 'chmod', 'u-s', line], stdout=subprocess.PIPE)





def solutions(ports, firewall):
    print("\n\nI can solve for you the following problems:")
    if security_updates != []:
        print("Download and install security updates. (To select this option type update)")
    if file_permision != []:
        print("Change the file permisions.(To select this option type permissions)")
    if ssh_problems != []:
        print("Fix ssh problems.(To select this option type ssh)")
    if ports != []:
        print("Close open ports.(To select this option type ports)")
    if firewall != []:
        print("Turn on firewall.(To select this option type firewall)")
    if setuidFiles != []:
        print("Remove the setuid bit from files.(To select this option type setuid)")
    print("if you want to enter more than one option separate them by ','.")
    option = ""
    option = input()
    options = option.split(",")
    for item in options:
        if item == "update":
            get_securityUpdates()
        elif item == "permissions":
            change_permissions()
        elif item == "ssh":
            update_ssh_config()
        elif item == "ports":
            close_ports(open_ports_global)
        elif item == "firewall":
            activate_firewall()
        elif item == "setuid":
            remove_setuid_bit()
        else:
            print("\n")
            print("You did not enter a corect option. Please try again!!!")

def menu():
    print("Python Security Script")
    print(os.getcwd())
    check_security_updates()
    check_permissions()
    time.sleep(5)
    suspiciousProcesses=check_suspicious_processes()
    time.sleep(5)
    check_setuid_files()
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

    print("\n\n\n")

    print("Problemele gasite sunt urmatoarele:")
    if security_updates != []:
        print("Aceste actualizari de securitate sunt disponibile")
        for line in security_updates:
            print(line)
    if file_permision != []:
        for line in file_permision:
            print(line)
    if setuidFiles != []:
        print("The following files have the setuid bit set:")
        for line in setuidFiles:
            print(line)
    print("If any of the following user should not be in the root or be in the sudo group please remove them.")
    for line in issues:
        print(line)
    print("\n")
    if suspiciousProcesses != []:
        for line in suspiciousProcesses:
            print(line)
    if ssh_problems != []:
        for line in ssh_problems:
            print(line)
    if ports != []:
        for line in ports:
            print(line)
    print(firewall[0])
    print(rootkit[0])
    check_CVE_2016_5195()
    solutions(ports,firewall)




menu()
