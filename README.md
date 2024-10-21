# User-Management-and-Access-Control-Using-Linux
User Management and Access Control in Multi-Tiered Organizational Structures

# Report Analysis

The assignment involved configuring user accounts, permissions, password policies, and logging on Linux systems to align with a defined organizational structure. The company had five groups with varying levels of access: Systems Administrator, CEO, Administration, Managers, and Unknown. The goal was to implement a robust security framework that reflected these hierarchical permissions. 

The project focused on the following key tasks:
- **User Management**: Creating users and assigning them to appropriate groups based on their roles.
- **Permission Configuration**: Establishing detailed access controls for resources to ensure that only authorized personnel can access sensitive data.
- **Password Policy Enforcement**: Implementing strong password requirements and aging policies to enhance security.
- **User Restrictions**: Limiting user actions to mitigate potential security threats.
- **Event Logging**: Configuring logging mechanisms to monitor user activities and detect suspicious actions.
- **Ownership and Permissions**: Adjusting ownership and permissions for files and directories to ensure proper access control.
- **Privileged User Monitoring**: Setting up systems to log and audit actions performed by privileged users.

The project aims to provide a solid foundation for safeguarding the Linux system and its resources while ensuring compliance with organizational security policies.

## LINUX OS - Implementation

### Key Tasks and Implementation - Linux

#### User Management and Permissions
- **User Creation**: Created multiple users representing different roles within the organization, including Systems Administrator, CEO, Accountant, Administrator, Managers, and Unknown.
- **Group Assignment**: Assigned users to appropriate groups based on their roles.
- **Permission Configuration**: Established granular permissions for user accounts and groups, allowing fine-grained control over access to resources.
- **Directory Permissions**: Set permissions for directories general and special to ensure appropriate access levels.

#### Password Policy Enforcement
- **Complexity Requirements**: Enforced strong password policies, requiring a combination of uppercase and lowercase letters, numbers, and special characters.
- **Password Aging**: Implemented password aging policies to prevent the reuse of old passwords.
- **PAM Configuration**: Modified `/etc/pam.d/common-password` to enforce password complexity and aging rules.

#### User Restrictions
- **Terminal Access**: Prohibited certain users from accessing the terminal using:
    ```bash
    usermod -s /usr/sbin/nologin <username>
    ```
- **Command Restrictions**: Restricted the use of specific commands by modifying the user's `.bashrc` file.

#### Event Logging
- **Rsyslog Configuration**: Enabled rsyslog and configured it to log authentication and system events.
- **Rule Creation**: Defined rules in `/etc/audit/audit.rules` to capture specific events related to privileged user actions, user accounts, group information, and file access.

#### Ownership and Permissions
- **Ownership Changes**: Used `chown` to transfer ownership of files and directories as needed.
    ```bash
    sudo chown <new_owner>: <file_or_directory>
    ```
- **Permission Modifications**: Employed `chmod` and `setfacl` to set appropriate permissions for files and directories, ensuring proper access control.

#### Privileged User Logging
- **Auditd Configuration**: Enabled auditd and configured rules to monitor privileged user actions.
- **Rule Creation**: Defined rules to log commands executed by the root user, changes to user accounts, group information, and access to sensitive files.

### Security Framework Effectiveness
The implemented security framework effectively addresses key security concerns by:
- Establishing strong user access controls.
- Enforcing robust password policies.
- Monitoring user activity.
- Restricting sensitive actions.
- Protecting privileged users.

Overall, this implementation provides a solid foundation for safeguarding the Linux system and its resources. Regular review and updates are recommended to maintain the effectiveness of the security measures.

## 1. Setting Access Permissions

### Privileged account
Command:
```bash
sudo su
```
![image](https://github.com/user-attachments/assets/77ea4da6-3c4d-4923-aefe-a012926b2f67)

### Create Groups:
Command:
```bash
groupadd systems-admin
```
![image](https://github.com/user-attachments/assets/438f212d-9fb1-4b57-9ff5-cdedf9109006)

### Creating new users, assigning passwords, and assigning them to groups
Command Syntax:
```bash
useradd -m -G <Group name> -p <password> <user>
```
![image](https://github.com/user-attachments/assets/c5e7e0ae-0555-4b7e-9541-1613a5868620)
- -m: Creates the user's home directory.
- -G : Assigns the user to the specified group.
- -p : Sets a password for the user. In this case test123 is the password

### Create Directories
Command:
```bash
mkdir general
mkdir special
```
![image](https://github.com/user-attachments/assets/79db8d17-af4e-4ad0-9936-7a14b1f11b7a)

### Set Directory Permissions
Command:
![image](https://github.com/user-attachments/assets/b7a99c37-fb55-4358-b026-9c02b09e1df3)

- chown :Administrations general
  Changes the group ownership of the general directory to Administrations.
- chmod 777 general
  Sets permissions for general so that everyone (owner, group, others) can read, write, and execute.
- chown :Administrations special
  Changes the group ownership of the special directory to Administrations.
- chmod 770 general
  Sets permissions for general to allow full access (read, write, execute) for the owner and group, but no access for others.
These commands set group ownership for two directories and adjust permissions for general to control who can access it.

## 2. Granting Specific Permissions to Users 
CEO Directory: /home/boss – Assign write permission to Alice (Accountant)
Commands:
![image](https://github.com/user-attachments/assets/af6a6306-71c2-486d-9924-72cbe92d4e99)

- **chown Boss /home/boss** - This command changes the ownership of the directory /home/boss to the user Boss.
- **chmod 770 /home/boss** - This sets the permissions for the /home/boss directory to:
    7 (Owner): Full permissions (read, write, execute) for the owner (Boss).
    7 (Group): Full permissions for the group (if any is set).
    0 (Others): No permissions for anyone else.
**setfacl -m u:Alice:rwx /home/boss** - This adds an ACL entry that grants Alice read, write, and execute permissions on the **/home/boss** directory, even if she is not part of the group that owns it.
As a result, Boss has full control over the /home/boss directory, while Alice is granted complete access (read, write, execute) through the ACL, allowing her to interact with the directory despite the default restrictions for others.

## 3. Establishing Password Policies
**Edit PAM Configuration:**
  **Edit** /etc/pam.d/common-password to enforce password policies.
  - Minimum password length: 12 characters
  - Password complexity: At least one uppercase letter, one lowercase letter, one digit, and one special character
  - Password aging: Passwords must be changed every 90 days, and users will be warned 7 days before expiration
![image](https://github.com/user-attachments/assets/c567a453-7116-4128-a3b2-21fab6ea0dd5)

- **Password length:**
  **minlen:** Minimum password length
- **Password complexity:**
  **ucredit:** Minimum number of uppercase letters (ucredit=-1 for at least one uppercase letter)
  **lcredit:** Minimum number of lowercase letters
  **dcredit:** Minimum number of digits
  **ocredit:** Minimum number of special characters
- **Password aging:**
  **retry:** Maximum number of failed login attempts before the account is locked
  **age:** Minimum password age
  **warn:** Number of days before password expiration that the user will be warned
To apply the changes, run the following command:
```bash
sudo pam-auth-update --verbose
```
![image](https://github.com/user-attachments/assets/7004d258-a364-493a-a58d-eb216af075c5)

To modify the password aging settings for a specific user using the chage command, the following options can be used:
- -m: Sets the minimum number of days between password changes.
- -M Sets the maximum number of days between password changes.
- -W: Sets the number of days before password expiration that the user will be warned.

For example, 
``` bash
sudo chage -m 30 -M 60 -w 7 alice
```
![image](https://github.com/user-attachments/assets/9a9f107f-29ee-4f81-8009-c1804c6d15f5)

This command sets the minimum password age for the user Alice to 30 days, the maximum password age to 60 days, and the warning period to 7 days.

## 4. Restricting User Actions
Prohibit employees from accessing terminal (CLI), using a certain command.
**Prohibit Access to the Terminal (CLI)**
Change the user's shell to a non-login shell, such as **/usr/sbin/nologin**, which prevents them from accessing the terminal.
Command: 
```bash
sudo usermod -s /usr/sbin/nologin tom
```
![image](https://github.com/user-attachments/assets/e33c5f84-3352-47b9-b42e-9445ad662724)
 
**Verify if it worked:** 
```bash
cat /etc/passwd | grep tom
```
![image](https://github.com/user-attachments/assets/363d8e38-e4b1-44df-ba2d-fd2f2819b3bd)
 
When **/sbin/nologin** is set as the shell, if the user with that shell logs in, they'll get a polite message saying **'This account is currently not available'**. This message can be changed with the file **/etc/nologin.txt**. If you prefer a silent denial, use **/bin/false**.

### Restrict Usage of Certain Commands
To restrict specific commands, you can use chmod to remove execute permissions for those commands or set up an alias that gives a warning or does nothing. 
For example, to restrict mkdir: edit user’s **.bashrc** file and writing basic commands to deny access. 
**Example**: We will deny root-exploit from using the command **mkdir**. First open the **.bashrc** file then edit. 
Command: 
```bash
sudo nano /home/root-exploit/.bashrc
```
The basic script was added at the top of the **.bashrc** file
```bash
# vi ~/.bashrc
/bin/mkdir() {
        echo "Permission denied"
}
mkdir() {
        echo "Permission denied”
}
./mkdir() {
        echo "Permission denied"
}
readonly -f /bin/mkdir
readonly -f mkdir
readonly -f ./mkdir
```
![image](https://github.com/user-attachments/assets/92a03518-8f94-4c38-9d96-9bd7ea9009f9)

**Test to verify:**
![image](https://github.com/user-attachments/assets/bb56a015-51c2-4adb-a683-ef84e91468c7)
User denied permission, cannot run the mkdir command.

## 5. Enabling Event Logging 
Check rsyslog Status - Command: 
```bash
systemctl status rsyslog
```
**Output:** If rsyslog is active and running, you'll see a message like **"rsyslog.service - system logging service (syslogd)"** followed by **"Active: active (running)"**.
If not running: Start it using 
```bash
sudo systemctl start rsyslog.
```
![image](https://github.com/user-attachments/assets/1a577169-b7f9-4ba7-a421-1ce19a36f8d4)

### Activating event logs (Authentication/Syslog) - rsyslog
Command:
```bash
authpriv.* /var/log/auth.log
*.*;auth,authpriv.none -/var/log/syslog
```

**Breakdown of Each Line**
- **authpriv.*** **/var/log/auth.log**
    - **authpriv.*:** Captures all log messages related to the authpriv facility, which deals with security and authorization (e.g., login attempts).
    - **/var/log/auth.log**: Stores all authentication-related logs.
- ***.*;auth,authpriv.none** **-/var/log/syslog**
    - **\*.\*:** Captures all log messages from every facility.
    - **;auth,authpriv.none:** Excludes messages from the auth and authpriv facilities.
    - **-/var/log/syslog:** Logs remaining messages to /var/log/syslog in a non-blocking manner for improved performance.

![image](https://github.com/user-attachments/assets/f78697e5-aee4-4d8b-825d-dcc305894e4f)

The first line logs all authentication-related messages to /var/log/auth.log.
The second line logs all other messages to /var/log/syslog, excluding authentication messages.
This setup helps organize logs, making it easier to monitor authentication events separately.

## 6. Taking Ownership of Files 
A directory rootFolder is created by root, owned it as listed.

![image](https://github.com/user-attachments/assets/6bf0fe3a-0381-436d-ba4c-2bd6ad5af29a)

Taking ownership from root, godmode claims full control the directory as the new owner.
Command:
```bash
sudo chown godmode: /home/rootFolder
```
Check:
```bash
ls -la
```
![image](https://github.com/user-attachments/assets/c84e8a11-d9d0-4efa-9d89-7ac499805179)

### Implementing SUID, SGID/GUID and Sticky bit
Using the numerical method, we need to pass a fourth, preceding digit in our chmod command. The digit used is calculated similarly to the standard permission digits:
- Start at 0
- SUID = 4
- SGID = 2
- Sticky = 1
The syntax is: **$ chmod X### file | directory**

**SUID (Set User ID)**
Command:
```bash
sudo chmod 4770 /home/rootFolder
```
![image](https://github.com/user-attachments/assets/584d4389-bad1-477d-89bc-7bfa063e2d47)

**Effect:** Sets the SUID bit, allowing executables to run with the privileges of the file owner. For directories, this is less common and can pose security risks. Permissions allow owner and group full access, while others have none.

**SGID (Set Group ID)**
Command:
```bash
sudo chmod 2770 /home/rootFolder
```
![image](https://github.com/user-attachments/assets/888ae596-2c70-4129-8299-cbcda8c361df)

**Effect:** Sets the SGID bit, ensuring files created in the directory inherit the group of the directory, promoting collaboration. Permissions allow owner and group full access, while others have none.

**Sticky Bit**
Command:
```bash
sudo chmod 1770 /home/rootFolder
```
![image](https://github.com/user-attachments/assets/8fb24380-9faf-47c7-b7ef-3566b51d04d0)

**Effect:** Sets the sticky bit, restricting file deletion to only the file owner or the root user, enhancing security in shared directories. Permissions allow owner and group full access, while others have none.
These commands configure access and behavior for the specified directory, enhancing security and collaboration through specific permission settings.

## 7. Creating and Managing User Accounts - Complex Access Control
**Create Additional Users:** You can add more users as needed:
Command:
```bash
sudo adduser debian
sudo adduser elvis
```
![image](https://github.com/user-attachments/assets/4a5ba22d-203d-4260-98aa-2674e393d422)

**Set Default ACLs:** To ensure that new files created in a directory inherit specific permissions:
This sets the default permissions for new files created in /home/general:
Alice gets read, write, and execute permissions. 
Bob gets read and execute permissions.
Command:
```bash
sudo setfacl -d -m u:debia:rwx /home/rootFolder
sudo setfacl -d -m u:elvis:r-x /home/rootFolder
```
![image](https://github.com/user-attachments/assets/df08a3ab-1c95-4a8a-9280-8bc93ac9b849)

- setfacl: This is the command used to set file access control lists (ACLs). ACLs provide a more flexible permission mechanism compared to the traditional owner/group/other model.
- -d: This option sets default ACLs. Default ACLs apply to newly created files and directories within the specified directory. They determine what permissions new files will have by default.
- -m: This option stands for "modify." It allows you to modify the existing ACLs.

The command effectively sets up default permissions for the user Bob on the /home/general directory, allowing Bob to read and execute files within that directory, while preventing him from making any modifications. Any new files or directories created inside /home/general will inherit these default permissions.

**More Complex Permissions and ACL**
Each user has full permissions to the objects he creates, and for other objects from the same group the user belongs – read-only permissions.

![image](https://github.com/user-attachments/assets/25bb88f8-9385-4973-8119-785d2bb84c1f)
![image](https://github.com/user-attachments/assets/cfa8cf48-ca88-4924-a147-b12263d32684)

 
**Setting Default ACLs**
Command:
```bash
setfacl -d -m u::rw-,g::r--,o::r-- shared_dir
```
The command **setfacl -d -m u::rw-,g::r--,o::r-- shared_dir** sets default Access Control Lists (ACLs) for the directory **shared_dir** as follows:
- **u::rw-**: The file owner has read and write permissions.
**- g::r--**: The group has read-only permissions.
- **o::r--**: Others have read-only permissions.

**Effect**
When a user creates a file in shared_dir, the file will:
- Allow the owner to read and write.
- Allow group members and others to read only.
- This setup prevents users from modifying files they do not own while enabling file creation.

![image](https://github.com/user-attachments/assets/387da0c5-581a-451c-8bfb-a513bc9a447a)

The **shared_dir** directory is owned by the root user and group, and has read, write, and execute permissions for everyone. The **t** flag ensures that only the owner or root can modify the contents of the directory. New files created within the directory will have **read-only permissions** for members of the root group and others, while the owner will have read and write permissions.
This setup is useful for shared directories where you want to allow file creation but restrict modifications by users who do not own the files.

## 8. Implementing Privileged User Logging and Sessions 
Open the rules file to define what events to log. - Add Audit Rules for Privileged Actions
Command:
```bash
sudo nano /etc/audit/audit.rules
```
![image](https://github.com/user-attachments/assets/a8cad158-9c88-464b-b3b0-096391955a98)
```bash
# Log all commands executed by the root user
-a always,exit -F arch=b64 -S execve -C uid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -C uid=0 -k root_commands

# Log changes to user accounts
-w /etc/passwd -p wa -k user_changes
-w /etc/shadow -p wa -k user_changes

# Log changes to group information
-w /etc/group -p wa -k group_changes

# Log access to sensitive files
-w /etc/sudoers -p wa -k sudoers_access
-w /etc/hosts -p wa -k hosts_access

# Log service management actions
-w /usr/bin/systemctl -p x -k service_management
```
![image](https://github.com/user-attachments/assets/3d31fe07-2b7b-42d6-b4f8-a1fbd65e650a)

**Rule Breakdown:**
- **-a always,exit**: Logs every exit from the specified system calls.
- **-F arch=b64**: Targets 64-bit architecture, use b32 for 32-bit.
- **-S execve**: Monitors the execution of commands.
- **-C uid=0**: Filters to log only actions taken by the root user.
- **-w <path> -p wa -k <key>**: Watches a specified file or directory for write (w) and attribute (a) changes, tagging with a key for easy searching.

**Restart the Audit Daemon:**
Command:
```bash
sudo systemctl restart auditd
```
This applies the new rules to the audit system.

![image](https://github.com/user-attachments/assets/9d02b147-2587-4d43-aeb7-05b61e5e9951)

## 9. Verifying Granted Permissions 
Command:
```bash
sudo getfacl /home/*
```

The command **sudo getfacl /home/*** is used to retrieve the Access Control Lists (ACLs) for all files and directories within the /home directory.
Here's a breakdown of what each part does:
- **getfacl**: This command is specifically designed to retrieve ACLs for files and directories.
- **/home/***: This is a wildcard expression that expands to all files and directories within the /home directory.

![image](https://github.com/user-attachments/assets/57448841-8430-49ee-8e91-f8c4c9d3e3b6)

The command will list the ACLs for all files and directories in the /home directory, showing you the permissions granted to different users and groups. This is useful for understanding how access is controlled for these files and directories.





