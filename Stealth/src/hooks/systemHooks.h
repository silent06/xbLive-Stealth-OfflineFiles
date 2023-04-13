#pragma once

class SystemHooks {
public:
	static HRESULT Initialize();
	//static void NetDll_XnpSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, PXOSC_BUFFER* respBuff, DWORD respSize);
	static int XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress);
	static bool XexCheckExecutablePrivilegeHook(int priviledge);
	static HRESULT XexStartExecutableHook(FARPROC TitleProcessInitThreadProc);
	static void XSecurityCloseProcessHook();
	static void APCWorker(void* Arg1, void* Arg2, void* Arg3);
	static int XSecurityCreateProcessHook(int dwHardwareThread);
	static int XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	static int XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation);
	static void* RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey);
	static long long XeKeysExecuteHook(XE_KEYS_BUFFER* buffer, int fileSize, byte* salt, long long input2, long long input3, long long input4);


	static void XNotifyQueueUIHook(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam);
	static int NetDll_connectHook(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length);
	static DWORD XamShowMessageBoxUIHook(DWORD dwUserIndex, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, DWORD dwFlags, PMESSAGEBOX_RESULT pResult, PXOVERLAPPED pOverlapped);
	static HRESULT XamShowMessageBoxHook(DWORD unk, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, MBOXRESULT resFun, DWORD dwFlags);
	static void* XexPcToFileHeaderHook(DWORD pAddress, PLDR_DATA_TABLE_ENTRY* ldatOut);
};

static DWORD(__cdecl *xeKeysExecute)(PVOID pvPhyBuffer, DWORD len, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4) = (DWORD(*)(PVOID, DWORD, PVOID, PVOID, PVOID, PVOID))0x80109FF8;

#ifndef _xosc__H 
#define _xosc__H
//#include "stdafx.h"

#pragma pack(1)
typedef struct _XOSC_BUFFER {
	DWORD dwResult; //0x0
	WORD MajorVersion; //0x4
	WORD MinorVersion; //0x6
	QWORD qwflags; //0x8
	NTSTATUS DvdInqResp; //0x10
	NTSTATUS XeikaInqResp; //0x14
	NTSTATUS executionIdResponse;//0x18
	NTSTATUS HvIdCacheDataResp; //0x1C
	NTSTATUS MediaInfoResp; // 0x20
	DWORD MediaInfodwUnk1; //0x24
	DWORD MediaInfodwUnk2; //0x28
	DWORD MediaInfoAbUnk; //0x2C
	DWORD MediaInfoPad5; //0x30
	DWORD HwMaskTemplate; //0x34
	BYTE xexExecutionId[0x18]; //0x38
	BYTE hvCpuKeyHash[0x10]; //0x50
	BYTE xexHashing[0x10]; //0x60
	BYTE zeroEncryptedConsoleType[0x10]; //0x70
	BYTE DvdXeikaPhaseLevel[0x3]; //0x80
	BYTE drivePhaseLevel; //0x83 
	DWORD dwMediaType; //0x84
	DWORD dwTitleId; //0x88
	BYTE DvdPfiInfo[0x11]; //0x8C
	BYTE DvdDmiMediaSerial[0x20]; //0x9D
	BYTE DvdMediaId1[0x10]; //0xBD
	BYTE abPad[0x03]; //0xCD
	QWORD DvdDmi10Data; //0xD0
	DWORD DvdGeometrySectors; //0xD8
	DWORD DvdGeometryBytesPerSector; //0xDC
	BYTE DvdMediaId2[0x10]; //0xE0
	BYTE DvdInqRespData[0x24]; //0xF0 
	BYTE XeikaInqData[0x24]; //0x114
	BYTE consoleSerial[0xC]; //0x138
	WORD serialByte; //0x144
	WORD hvHeaderFlags; //0x146
	WORD hvUnrestrictedPrivs; //0x148 
	WORD kvOddFeatures; //0x14A
	DWORD hvUnknown; //0x14C
	DWORD kvPolicyFlashSize; //0x150
	DWORD kvRestrictedStatus; //0x154
	DWORD hvKeyStatus; //0x158
	DWORD dwPad1; //0x15C
	QWORD secDataDvdBootFailures; //0x160
	DWORD secDataFuseBlowFailures; //0x168
	DWORD dwPad2; //0x16C
	QWORD HardwareMask; //0x170
	DWORD secDataDvdAuthExFailures; //0x178
	DWORD secDataDvdAuthExTimeouts; //0x17C
	QWORD kvRestrictedPrivs; //0x180
	QWORD hvSecurityDetected; //0x188
	QWORD hvSecurityActivated; //0x190
	QWORD hvProtectedFlags; //0x198
	BYTE consoleId[0x5]; //0x1A0
	BYTE _unk14[0x2B]; //0x1A5
	DWORD XboxHardwareInfoFlags; //0x1D0
	BYTE HddSerialNumber[0x14]; //0x1D4
	BYTE HddFirmwareRevision[0x08]; //0x1E8
	BYTE HddModelNumber[0x28]; //0x1F0
	BYTE HddUserAddressableSectors[0x04]; //0x218
	BYTE unkMediaInfo[0x80];  //0x21C
	QWORD DvdUnkp1; //0x29C
	DWORD MediaInfoUnkp3; //0x2A4
	DWORD MemoryUnit0; //0x2A8
	DWORD MemoryUnit1; //0x2AC
	DWORD InMuSfcAu; //0x2B0
	DWORD IntMuUSBAu; //0x2B4
	DWORD UsbMu0PartitionFileSize; //0x2B8
	DWORD UsbMu1PartitionFileSize; //0x2BC
	DWORD UsbMu2PartitionFileSize; //0x2C0
	DWORD crlVersion; //0x2C4
	QWORD Layer0PfiSectors; //0x2C8
	QWORD Layer1PfiSectors; //0x2D0
	DWORD respMagic; //0x2D8
	DWORD dwFinalPad; //0x2DC
	BYTE NulledBuffer[0x120]; //0x2E0
} XOSC_BUFFER, *PXOSC_BUFFER;
C_ASSERT(sizeof(XOSC_BUFFER) == 0x400);
#pragma pack()
#endif