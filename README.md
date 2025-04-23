# Simple Process Injection Script (Windows)

This repository contains a simple Windows process injection script written in C++. The script demonstrates how to inject shellcode into a target process using Windows API functions. It is important to note that this script is designed for educational purposes and does not include any evasive measures or anti-detection techniques.

## Overview

The script performs the following steps:
1. Opens the target process using `OpenProcess` with the required access rights.
2. Allocates memory in the target process's virtual space using `VirtualAllocEx`.
3. Writes the shellcode into the allocated memory using `WriteProcessMemory`.
4. Creates a remote thread in the target process to execute the injected shellcode using `CreateRemoteThread`.

## Usage

1. Compile the script using a C++ compiler that supports Windows API (e.g., Visual Studio).
2. Modify the `pid` variable to the process ID of the target process.
3. Modify the `shellcode[]` array with the desired shellcode.
4. Run the compiled executable.

### Example:
```cpp
DWORD pid = 26636; // Replace with the target process ID
unsigned char shellcode[] = {0x90}; // Replace with your shellcode
```

## Disclaimer
This script is intended for educational and research purposes only. Unauthorized use of process injection techniques can be illegal and unethical. Always ensure you have permission before testing or using these techniques on systems you do not own or have explicit consent to interact with.

