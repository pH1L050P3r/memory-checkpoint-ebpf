The project leveraging eBPF for efficient memory checkpointing & restoration, enabling lightweight process monitoring, capturing snapshots, and restoring memory states seamlessly, using BPF maps and BCC integration for minimal overhead, optimized for low-latency execution, serving as a modern alternative to CRIU-based checkpointing, enhancing Linux process management with high performance, reduced system calls, and efficient memory state tracking, making it an innovative solution for process persistence, fault tolerance, and system recovery.

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
