# PEB from errno
A funny way of getting PEB through the reutilization of existing legitimate code. No generation of `mov rax, qword ptr gs:[0x60]` or similar instructions required.