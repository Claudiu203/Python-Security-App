import os
import tkinter as tk
import spwd
import subprocess


suspiciousProcesses = []
setuidFiles = []

def check_file_permissions():
    files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"]
    for file in files:
        if os.path.exists(file):
            perms = oct(os.stat(file).st_mode)[-3:]
            print(f"Permissions for {file}: {perms}")
            if int(perms) > 644:
                print(f"Warning: {file} has permissions greater than 644")
        else:
            print(f"{file} does not exist.")

def get_securityUpdates():
    print("Checking for security updates....")
    os.system("sudo apt-get update")
    os.system("sudo apt-get upgrade -s | grep -i security")

def check_users_and_groups():
    print("Checking for users with empty passwords...")
    for user in spwd.getspall():
        if user.sp_pwd == '':
            print(user.sp_namp)

    print("Checking for disabled accounts...")
    for user in spwd.getspall():
        if user.sp_pwd == '!':
            print(user.sp_namp)

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
                print("Warning: PermitRootLogin should be set to 'no'")
            if "PasswordAuthentication no" not in config:
                print("Warning: PasswordAuthentication should be set to 'no'")
    else:
        print("sshd_config file does not exist.")

def check_open_ports():
    print("Checking open ports...")
    os.system("sudo netstat -tulpn")

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

print(os.getcwd())
#get_securityUpdates()
check_file_permissions()
check_users_and_groups()
check_suspicious_processes()
check_ssh_configuration()
check_open_ports()
check_setuid_files()
check_system_logs()
check_CVE_2016_5195()


root = tk.Tk()
root.title("Linux Security Vulnerabilities")

# Create a scrollbar
scrollbar = tk.Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Create a listbox to display the vulnerabilities
listbox = tk.Listbox(root, yscrollcommand=scrollbar.set, width=100, height=20)
listbox.pack(side=tk.LEFT, fill=tk.BOTH)
scrollbar.config(command=listbox.yview)

# Create a button to check for vulnerabilities
check_button = tk.Button(root, text="Check Vulnerabilities", command=)
check_button.pack()

# Start the Tkinter main loop
root.mainloop()