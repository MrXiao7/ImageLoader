#include "PeTools.h"

/*-----------------------------PE����----------------------------------------*/
/*����PE����*/
PUCHAR FileToImage(PUCHAR ptr)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)ptr);
	ULONG SectionNum = nt->FileHeader.NumberOfSections;
	ULONG SizeOfImage = nt->OptionalHeader.SizeOfImage;
	PUCHAR imagePtr = ExAllocatePool(NonPagedPool,SizeOfImage);
	RtlZeroMemory(imagePtr, SizeOfImage);

	RtlCopyMemory(imagePtr, ptr, nt->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER SectionBase = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < SectionNum;i++) 
    {
		RtlCopyMemory((ULONG)imagePtr + SectionBase->VirtualAddress, (ULONG)ptr + SectionBase->PointerToRawData, SectionBase->SizeOfRawData);
		SectionBase++;
	}

	return imagePtr;
}

/*�޸��ض�λ*/
VOID FixReloc(PUCHAR ptr,ULONG isNeedFixCookie)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)ptr);
	PIMAGE_DATA_DIRECTORY pReloc = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ULONG ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_BASE_RELOCATION relocAddr = (PIMAGE_BASE_RELOCATION)((ULONG)ptr + pReloc->VirtualAddress);
	
	while (relocAddr->VirtualAddress && relocAddr->SizeOfBlock) 
    {
		
		PUCHAR RelocBase = (PUCHAR)((ULONG)ptr + relocAddr->VirtualAddress);
		ULONG BlockNum = relocAddr->SizeOfBlock / 2 - 4;
		for (ULONG i = 0; i < BlockNum;i++) {
			ULONG Block = *(PUSHORT)((ULONG)relocAddr + 8 + 2 * i);
			ULONG high4 = Block & 0xF000;
			ULONG low12 = Block & 0xFFF;
			PULONG RelocAddr = (PULONG)((ULONG)RelocBase + low12);
			if (high4 == 0x3000)
            {
				*RelocAddr = *RelocAddr - ImageBase + (ULONG)ptr;
                PULONG cookiePtr = (PULONG)(*RelocAddr);
                if (isNeedFixCookie && *cookiePtr == 0xB40E64E)
                {
					*cookiePtr = 0x65083911;
				}
			}
		}
		relocAddr = (PIMAGE_BASE_RELOCATION)((ULONG)relocAddr + relocAddr->SizeOfBlock);
	}
}

/*�޸������*/
VOID FixImport(PUCHAR ptr) 
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ptr;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)ptr);
	ULONG ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY pImport = &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	PIMAGE_IMPORT_DESCRIPTOR importDes = pImport->VirtualAddress + ptr;

	while (importDes->Name)
	{
		ULONG ModuleSize = 0;
		ULONG_PTR base = GetKernelModuleBase(importDes->Name+ptr, &ModuleSize);
		PULONG pImData = (PULONG)(importDes->FirstThunk + ptr);
		
		while (*pImData)
		{
			PIMAGE_IMPORT_BY_NAME FuncName = *pImData + ptr;
			ULONG FuncAddr = (ULONG)GetExportFuncAddr(base, FuncName->Name);
			*pImData = FuncAddr;
			pImData++;
		}
		importDes++;
	}
}

/*��ȡ����������ַ*/
PUCHAR GetExportFuncAddr(PUCHAR base,PUCHAR funcName)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)base);
	ULONG ImageBase = nt->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY pExport = &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY pExDir = pExport->VirtualAddress + base;
	ULONG NumberOfFuncs = pExDir->NumberOfFunctions;
	ULONG NumberOfNames = pExDir->NumberOfNames;
	PULONG AddrOfFuncs = pExDir->AddressOfFunctions + base;
	PULONG AddrOfNames = pExDir->AddressOfNames + base;
	PUSHORT AddrOfNameOrd = pExDir->AddressOfNameOrdinals + base;

	for (ULONG i = 0; i < NumberOfNames; i++)
	{
		PUCHAR preName = AddrOfNames[i] + base;
		if (!strcmp(funcName, preName))
        {
			return AddrOfFuncs[AddrOfNameOrd[i]] + base;
		}
	}
	return NULL;
}

/*ȡ��ڵ��ַ*/
PULONG GetEntryPoint(PCHAR base)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)base);
	return nt->OptionalHeader.AddressOfEntryPoint + base;
}

/*���PEͷ*/
VOID CleanPeHeader(PCHAR base)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG)base);
	RtlZeroMemory(base,nt->OptionalHeader.SizeOfHeaders);
}











/*------------------------------------------�ں˲���------------------------------------------*/




/*ȡ����ģ���ַ���С*/
ULONG_PTR GetKernelModuleBase(PUCHAR moduleName, PULONG pModuleSize) 
{
	RTL_PROCESS_MODULES SysModules = { 0 };
	PRTL_PROCESS_MODULES pModules = &SysModules;
	ULONG SystemInformationLength = 0;


	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pModules, sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
		pModules = ExAllocatePool(NonPagedPool, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		RtlZeroMemory(pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES));
		status = ZwQuerySystemInformation(SystemModuleInformation, pModules, SystemInformationLength + sizeof(RTL_PROCESS_MODULES), &SystemInformationLength);
		if (!NT_SUCCESS(status))
        {
			ExFreePool(pModules);
			return 0;
		}
	}

	if (!strcmp("ntoskrnl.exe", moduleName) || !strcmp("ntkrnlpa.exe.exe", moduleName))
    {
		*pModuleSize = pModules->Modules[0].ImageSize;
		ULONG_PTR ret = pModules->Modules[0].ImageBase;
		if (SystemInformationLength)
        {
			ExFreePool(pModules);
		}
		return ret;
	}

	for (ULONG i = 0; i < pModules->NumberOfModules; i++)
    {
		if (strstr(pModules->Modules[i].FullPathName, moduleName)) 
        {
			*pModuleSize = pModules->Modules[i].ImageSize;
			ULONG_PTR ret = pModules->Modules[i].ImageBase;
			if (SystemInformationLength) 
            {
				ExFreePool(pModules);
			}
			return ret;
		}
	}
	if (SystemInformationLength)
    {
		ExFreePool(pModules);
	}
	return 0;
}