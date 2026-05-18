savedcmd_/home/ubuntu/OS2/rootkit_hidden_module.mod := printf '%s\n'   rootkit_hidden_module.o | awk '!x[$$0]++ { print("/home/ubuntu/OS2/"$$0) }' > /home/ubuntu/OS2/rootkit_hidden_module.mod
