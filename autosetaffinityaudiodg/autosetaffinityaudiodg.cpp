#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

bool SetProcessAffinity(DWORD processId, DWORD affinityMask)
{
	// Open the process with PROCESS_QUERY_INFORMATION and PROCESS_SET_INFORMATION access rights
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, processId);
	if (process == NULL)
	{
		return false;
	}

	// Set the affinity mask
	if (!SetProcessAffinityMask(process, affinityMask))
	{
		CloseHandle(process);
		return false;
	}

	CloseHandle(process);
	return true;
}

bool SetProcessAffinityByName(const char* processName, DWORD affinityMask)
{
	// Find the process ID by name
	DWORD processId = 0;

	// Taking the snapshot of all the processes actually running
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot != INVALID_HANDLE_VALUE) // iteration of the snapshot
	{
		PROCESSENTRY32 processEntry = {0}; // struct containing the process information
		processEntry.dwSize = sizeof(processEntry);
		if (Process32First(snapshot, &processEntry))
		{
			do
			{
				if (strcmp(processEntry.szExeFile, processName) == 0)
				{
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}

	if (processId == 0)
	{
		return false;
	}

	// Modify the process affinity
	return SetProcessAffinity(processId, affinityMask);
}

void escalate_process() {

	// Get the handle of the current process
	HANDLE h_process = GetCurrentProcess();

	// Declare and initialize variables
	HANDLE h_token = NULL;
	LUID luid, debug_luid;
	BYTE tp_buffer[256];
	DWORD cb;

	// Open the access token associated with the current process
	if (!OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) {
		printf("OpenProcessToken failed: %d\n", GetLastError());
		return;
	}

	// Lookup the LUID for the SE_SYSTEMTIME_NAME privilege
	if (!LookupPrivilegeValue(NULL, SE_SYSTEMTIME_NAME, &luid)) {
		printf("LookupPrivilegeValueW failed: %d\n", GetLastError());
		return;
	}

	// Lookup the LUID for the SE_DEBUG_NAME privilege
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debug_luid)) {
		printf("LookupPrivilegeValueW failed: %d\n", GetLastError());
		return;
	}

	// Initialize the TOKEN_PRIVILEGES structure
	TOKEN_PRIVILEGES* tp = reinterpret_cast<PTOKEN_PRIVILEGES>(tp_buffer);
	tp->PrivilegeCount = 2;
	tp->Privileges[0].Luid = luid;
	tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp->Privileges[1].Luid = debug_luid;
	tp->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the SE_SYSTEMTIME_NAME and SE_DEBUG_NAME privileges
	if (!AdjustTokenPrivileges(h_token, FALSE, tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		printf("AdjustTokenPrivileges failed: %d\n", GetLastError());
		return;
	}

	// Get the TOKEN_PRIVILEGES structure for the access token
	cb = 0;
	if (!GetTokenInformation(h_token, TokenPrivileges, NULL, 0, &cb)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			printf("GetTokenInformation failed: %d\n", GetLastError());
			return;
		}
	}

	TOKEN_PRIVILEGES* new_tp = (TOKEN_PRIVILEGES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
	if (!new_tp) {
		printf("HeapAlloc failed: %d\n", GetLastError());
		return;
	}

	if (!GetTokenInformation(h_token, TokenPrivileges, new_tp, cb, &cb)) {
		printf("GetTokenInformation failed: %d\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, new_tp);
		return;
	}

	bool found1 = false;
	bool found2 = false;
	for (DWORD i = 0; i < new_tp->PrivilegeCount; ++i) {
		if ((new_tp->Privileges[i].Luid.LowPart == luid.LowPart && new_tp->Privileges[i].Luid.HighPart == luid.HighPart)
			|| (new_tp->Privileges[i].Luid.LowPart == debug_luid.LowPart && new_tp->Privileges[i].Luid.HighPart == debug_luid.HighPart)) {
			if ((new_tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == 0) {
				std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
				return;
			}
			if (!found1) {
				found1 = true;
			}
			else {
				found2 = true;
			}
		}
		if (found1 && found2) {
			break;
		}
	}

	if (!found1 || !found2) {
		std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
		return;
	}

	HeapFree(GetProcessHeap(), 0, new_tp);
	CloseHandle(h_token);
}


int main() {

	// Get the permissions to manage other processes
	escalate_process();

	// Find a process named "audiodg.exe" and set its affinity to use only the second processor
	DWORD affinityMask = 0x00000001;
	bool success = SetProcessAffinityByName("audiodg.exe", affinityMask);
	if (success)
	{
		std::cout << "Process affinity set successfully." << std::endl;
	}
	else
	{
		std::cout << "Failed to set process affinity." << std::endl;
	}

	return 0;
}
