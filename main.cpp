#include <Windows.h>
#include <iostream>

BOOL InjectDLL(DWORD processId, const char* dllPath) {
    // Open a handle to the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process" << std::endl;
        return FALSE;
    }

    // Allocate memory in the target process to store the path to the DLL
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddr == NULL) {
        std::cerr << "Failed to allocate memory in remote process" << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the path to the DLL into the target process
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write to remote process memory" << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get the address of the LoadLibrary function in kernel32.dll
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Failed to get address of LoadLibrary function" << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, dllPathAddr, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

int main() {
    DWORD processId = 1234; // Replace with the process ID of the target game
    const char* dllPath = "YourInjectedDLL.dll"; // Replace with the path to your DLL

    if (InjectDLL(processId, dllPath)) {
        std::cout << "DLL injected successfully" << std::endl;
    } else {
        std::cerr << "DLL injection failed" << std::endl;
    }

    return 0;
}
