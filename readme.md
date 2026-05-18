insmod rootkit_hidden_module.ko
lsmod | grep rootkit_hidden_module
./detect_hidden_module

echo 0 > /sys/module/rootkit_hidden_module/parameters/hide
lsmod | grep rootkit_hidden_module

rmmod rootkit_hidden_module
./detect_hidden_module



