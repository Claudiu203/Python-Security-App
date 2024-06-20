import tkinter as tk
import subprocess
import os
import spwd
import pwd

def get_security_updates():
    updates = []
    result = subprocess.run(['sudo', 'apt-get', 'update'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    upgrade_result = subprocess.run(['sudo', 'apt-get', 'upgrade', '-s'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = upgrade_result.stdout.decode()
    for line in output.split('\n'):
        if 'security' in line.lower():
            updates.append(line)
    return updates

def get_file_permissions():
    permissions_issues = []
    files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers"]
    for file in files:
        if os.path.exists(file):
            perms = oct(os.stat(file).st_mode)[-3:]
            if int(perms) > 644:
                permissions_issues.append(f"Warning: {file} has permissions greater than 644")
    return permissions_issues

def get_users_and_groups():
    user_issues = []
    for user in spwd.getspall():
        if user.sp_pwd == '':
            user_issues.append(f"User {user.sp_namp} has an empty password.")
        if user.sp_pwd == '!':
            user_issues.append(f"User {user.sp_namp} account is disabled.")
    root_users = [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0]
    user_issues.append(f"Root users: {root_users}")
    return user_issues

def get_suspicious_processes():
    suspicious_issues = []
    result = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    suspicious_processes = ["nc", "netcat", "ncat", "perl", "python", "php", "ruby"]
    for line in output.split('\n'):
        for process in suspicious_processes:
            if process in line:
                suspicious_issues.append(line)
                break
    return suspicious_issues

def check_vulnerabilities():
    vulnerabilities = []
    vulnerabilities.extend(get_security_updates())
    vulnerabilities.extend(get_file_permissions())
    vulnerabilities.extend(get_users_and_groups())
    vulnerabilities.extend(get_suspicious_processes())
    return vulnerabilities

def update_listbox():
    vulnerabilities = check_vulnerabilities()
    listbox.delete(0, tk.END)
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            listbox.insert(tk.END, vulnerability)
    else:
        listbox.insert(tk.END, "No vulnerabilities found.")

# Create the main window
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
check_button = tk.Button(root, text="Check Vulnerabilities", command=update_listbox)
check_button.pack()

# Start the Tkinter main loop
root.mainloop()
