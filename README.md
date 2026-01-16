# Adaptive System Call Firewall (Operating Systems Project)

## Overview
This project demonstrates kernel-level enforcement of security using Linux
seccomp. The application allows only required system calls and blocks
unauthorized behavior at runtime.

## Problem Statement
Modern applications often execute unnecessary system calls, increasing the
kernel attack surface. Developers typically do not know which system calls are
required, leading to over-permissive execution.

## Objective
- Demonstrate OS-level syscall filtering
- Allow legitimate file operations
- Block unauthorized system calls such as network access
- Show kernel-enforced security using seccomp

## How to Run
```bash
gcc adaptive_app.c -o adaptive_app
echo "HELLO_FROM_KERNEL" > data.txt
./adaptive_app
HELLO_FROM_KERNEL
Attempting network access...
invalid system call
