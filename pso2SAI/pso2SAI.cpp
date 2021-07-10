#include <cstdint>
#include <iostream>
#include <string>

#include <windows.h>
#include <psapi.h>
#include <winternl.h>

#include "StUnknown.h"

inline DWORD detectProcess() {
	DWORD processId[0x2000];
	DWORD size;

	if (EnumProcesses(processId, sizeof(processId), &size) == 0)
		return NULL;

	for (int i = 0; i < size / sizeof(DWORD); i++) {
		HANDLE hProcess;
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId[i]);
		if (hProcess != NULL) {
			WCHAR path[MAX_PATH*2] = {0};
			GetProcessImageFileName(hProcess,path, sizeof(path) / sizeof(WCHAR));
			CloseHandle(hProcess);
			if (std::wstring(path).find(L"pso2.exe") != std::wstring::npos)
				return processId[i];

		}
	}
	return NULL;

}

inline uint64_t getRebootBase(HANDLE hProcess) {
	HMODULE hModule = LoadLibraryA("ntdll");
	NTSTATUS (*NtQueryInformationProcess)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
	NtQueryInformationProcess = (NTSTATUS(*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hModule,"NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION pbi;
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

	PEB peb;
	ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
	PEB_LDR_DATA pld;
	ReadProcessMemory(hProcess, peb.Ldr, &pld, sizeof(pld), NULL);
	LDR_DATA_TABLE_ENTRY pdte;
	ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)(pld.InMemoryOrderModuleList.Flink) - 0x10), &pdte, sizeof(pdte), NULL);
	for (int i = 0; i < 0x100; i++) {
		ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)(pdte.InMemoryOrderLinks.Flink) - 0x10), &pdte, sizeof(pdte), NULL);
		WCHAR* str = new WCHAR[pdte.FullDllName.MaximumLength];
		ReadProcessMemory(hProcess, pdte.FullDllName.Buffer, str, pdte.FullDllName.MaximumLength*sizeof(WCHAR), NULL);
		if (std::wstring(str).find(L"pso2reboot.dll") != std::wstring::npos)
			return (uint64_t)pdte.DllBase;
	}
	return 0;
}


int main() {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, detectProcess());
	if (hProcess == NULL) {
		std::cout << "pso2.exe couldnot detected." << std::endl;
		return 0;
	}
	uint64_t address = getRebootBase(hProcess);
	if (address==0) {
		std::cout << "pso2reboot.dll couldnot find." << std::endl;
		return 0;
	}
	ReadProcessMemory(hProcess, (LPCVOID)(address+0x22b5b58), &address, sizeof(address), NULL);
	ReadProcessMemory(hProcess, (LPCVOID)(address + 0x50), &address, sizeof(address), NULL);
	ReadProcessMemory(hProcess, (LPCVOID)(address + 0x10), &address, sizeof(address), NULL);
	StUnknown st;
	ReadProcessMemory(hProcess, (LPCVOID)address, &st, sizeof(st), NULL);
	uint8_t flag;
	for (int i = 0; i < 0x14; i++) {
		address = st.address[i];
		for (int j = 0; j < st.count[i]; j++) {
			ReadProcessMemory(hProcess, (LPCVOID)(address + j * 8 + 4), &flag, sizeof(flag), NULL);
			switch (flag) {
			case 0xAF:
				flag = 0xEF;
				break;
			case 0x9F:
				flag = 0xDF;
				break;
			case 0xBF:
				flag = 0xFF;
				break;
			}

			WriteProcessMemory(hProcess, (LPVOID)(address + j*8+4), &flag, sizeof(flag), NULL);
		}
	}
	std::cout << "success." << std::endl;


	return 0;
}