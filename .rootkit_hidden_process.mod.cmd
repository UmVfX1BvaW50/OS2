savedcmd_/home/ubuntu/OS2/rootkit_hidden_process.mod := printf '%s\n'   rootkit_hidden_process.o | awk '!x[$$0]++ { print("/home/ubuntu/OS2/"$$0) }' > /home/ubuntu/OS2/rootkit_hidden_process.mod
