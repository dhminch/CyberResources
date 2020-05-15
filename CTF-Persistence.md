# CTF Persistence

Non-exclusive list of ways to maintain persistence on a target in a CTF.

## Linux

- Hide tracks by moving real binaries and making a script that filters the output of the real binary. Could also be used to callback when the binary is run. Way easier than compiling a malicious copy. For example:
	1) Move /usr/bin/netstat to /usr/bin/netst
	2) Create script /usr/bin/netstat that calls /usr/bin/netst and `grep -v <YOUR_IP>`
	3) Use `touch -c -r <REF_FILE>` to modify the MAC times to blend in
- Make changes to files immutable so it is harder to undo the change if detected (i.e., use `chattr +i`)
- Modify sshd config and move where private keys are looked for, then add your keys
- Backdoor with ssh account, netcat
- Add backdoor webshell
- Crontab callback
- Bash alias callback
- Bash rc callback

## Windows

- Add new user accounts (hradmin, orangemaint, jenkin/jenkins)
- Jenkins hooks
