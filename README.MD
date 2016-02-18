This is lab2 assignment in UCLA CS111 Winter 16. In this lab2, I learned some basic kernel programming for the first time.
I implement the kernel module that supports LOCKED read/write. It is robust and able to check basic deadlock conditions(e.g. a process with write lock waiting for itself). However, the check is incomplete, it is not able to handle more complicated cases like circular waiting.

