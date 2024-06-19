This repository contains sample test cases for the programming assignment.

How to build:
-------------
Do "make" to build executables. <br />
"make clean" to remove them. <br />

Content:
--------
There are three executables. <br />
```
fork:     This measures the throughput of the fork-based method discussed in the assignment.
context:  This measures the throughput of your my_precious system call. Use it when your implementation is ready.
compare:  This can be used to compare fork-based method to your implementation. Use this for your final performance measurement when your implementation is ready.
```

Parameters:
-----------
All executables accept three parameters: <br />
```
t: Timeout (in seconds, default 60).
n: Number of elements in the buffer as power of 2 (default 1<<10). Use it to configure program size.
```
