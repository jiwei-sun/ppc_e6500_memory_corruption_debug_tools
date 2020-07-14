# ppc_e6500_memory_corruption_debug_tools
## monitor: monitoring userspace process's memory for e6500 core

## 1 What is it?
This tool is for debugging userspace application's memory corruption issue on PPC64 e6500 core.  

The tool includes two parts, one is kernel module, the other one is main monitor program which works on user space.  

The monitor program is used to record which thread has modified the shared memory.  
It can monitor a single memory(for example 0x10013010) or a range of memory(for example, 0x10013010-0x10013110). If you want to monitor a range of memory, the watchpoint kernel module is needed. It need to add some codes in the monitored process's source code, just as did in test.c.  

## 2 How to use it?  
2.1 Modifying the monitored task's source code, just as test.c  

2.2 Do not use watchpoint module  
It can just monitor a address with 4-byte aligned, such as 0x10013010, 0x10013014, 0x10013018, 0x1001301c and so on.  


```
#./test &  
[1] 466  
#./monitor -f /var/log/monitor_log -p 466
```
466 is test process pid, /var/log/monitor_log is a file for recording the information,  
And if a thread has modified the monitored memory, the log is as following  

```
Thu Jan  1 17:57:24 1970				---------> The is time
      The monitorted memory(0x10013010) is modifying by ------> what is the address
      task(pid:466, command:test)			  -------> which process and it's name
      thread(tid:470, command:thread_174)		  -------> which thread has modified, and it's name
      the current instruction address:0x10001378	---------> which instruction
      the old value:0xae				---------> the current value(before modified)
```

2.3 Using watchpoint module  
If you want to monitor any userspace address(not just 4-byte aligned), please using the watchpoint module.  

```
#insmod watchpoint.ko
#./test &
[1] 477
#./monitor -f /var/log/monitor_log -p 477
```

waiting for the monitor finished.

## 3 To Do List  
3.1 Modify the output form of the log，add backtrace  
3.2 Monitor the kernel space address.
