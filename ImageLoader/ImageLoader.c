#include <ntifs.h>
#include "PeTools.h"
#include "PeData.h"




VOID DriverUnload(PDRIVER_OBJECT pObj)
{

	DbgPrint("[Silky AIO]: Loader Driver Unloaded!\r\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pObj,PUNICODE_STRING reg)
{
	DbgBreakPoint();
	
	ULONG ModuleSize = 0;
	PUCHAR imageBase = FileToImage(peData);
	FixReloc(imageBase,TRUE);
	FixImport(imageBase);
	PULONG ep = GetEntryPoint(imageBase);
	ImageLoadDriverEntry epFunc = (ImageLoadDriverEntry)ep;
	CleanPeHeader(imageBase);
	epFunc(NULL, NULL);
	pObj->DriverUnload = DriverUnload;
	return STATUS_UNSUCCESSFUL;
}


