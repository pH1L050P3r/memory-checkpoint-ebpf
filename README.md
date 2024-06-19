This repository contains sample test cases for the programming assignment.

How to build:
-------------
Do "make" to build executables. <br />
"make clean" to remove them. <br />

Content:
--------
There are following files. <br />
```
testcase:     This runs the testcases and measures the latency.
checkpoint:  code for checkpointing, signal the eBPF to start checkpointing and recover.
utils:  Contains implementation of different testcases.
```

Parameters:
-----------
Executables accept two parameters: <br />
```
t: Timeout (in seconds, default 20).
n: Number of elements in the buffer as power of 2 (default 1<<10). Use it to configure program size.
```
