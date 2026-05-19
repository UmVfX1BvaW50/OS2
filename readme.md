# hidden module
insmod rootkit_hidden_module.ko
lsmod | grep rootkit_hidden_module
./detect_hidden_module

echo 0 > /sys/module/rootkit_hidden_module/parameters/hide
lsmod | grep rootkit_hidden_module

rmmod rootkit_hidden_module
./detect_hidden_module
# hidden process
sleep 9999 &
echo $!   # 记下 PID

insmod rootkit_hidden_process.ko target_pid=<PID>

ps -p <PID> -o pid,comm,stat
ls /proc | grep -x <PID>
insmod detect_hidden_process_kmod.ko
./detect_hidden_process
rmmod rootkit_hidden_module
./detect_hidden_process
