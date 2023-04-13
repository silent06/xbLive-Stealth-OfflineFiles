#include "stdafx.h"
#include "hooks/HV.h"

// title header

unsigned char dashExid[24] = {
	0x00, 0x00, 0x00, 0x00, 0x20, 0x44, 0x97, 0x00, 0x20, 0x44, 0x97, 0x00,
	0xFF, 0xFE, 0x07, 0xD1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// xexHash

unsigned char xam_da[88] = {
	0x00, 0x00, 0x2D, 0x94, 0x53, 0xD5, 0xD4, 0x39, 0xC7, 0xB0, 0x76, 0x38,
	0x1B, 0x44, 0x86, 0x1E, 0xEB, 0x45, 0x9D, 0x36, 0xCF, 0x47, 0x59, 0xC1,
	0x81, 0xA7, 0x3D, 0x04, 0x81, 0x5F, 0x0B, 0x34, 0x81, 0xA7, 0x3D, 0x14,
	0x81, 0x5F, 0x0B, 0x38, 0x81, 0xA7, 0x3D, 0x24, 0x78, 0x1E, 0x02, 0x60,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0x80, 0x00, 0x40, 0x04
};

unsigned char kernel_da[88] = {
	0x00, 0x00, 0x00, 0x20, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
	0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76, 0xC3, 0xD2, 0xE1, 0xF0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x45, 0x58, 0x32,
	0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00,
	0x80, 0x04, 0x0B, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x6D, 0xC0
};

unsigned char dash_da[88] = {
	0x00, 0x00, 0x4D, 0xEC, 0xC6, 0x2E, 0xC0, 0xF1, 0x9D, 0x93, 0x96, 0xB1,
	0xF1, 0xE9, 0x0A, 0x29, 0x92, 0x2F, 0xBD, 0x4C, 0xCD, 0xB4, 0x44, 0xEF,
	0x92, 0x00, 0x10, 0xC4, 0x92, 0x00, 0x10, 0xC8, 0x92, 0x93, 0xA4, 0x4C,
	0x92, 0x00, 0x10, 0xCC, 0x92, 0x93, 0xA4, 0x3C, 0x92, 0x00, 0x10, 0xD0,
	0x92, 0x93, 0xA4, 0x2C, 0x92, 0x00, 0x10, 0xD4, 0x92, 0x93, 0xA4, 0x1C,
	0x92, 0x00, 0x10, 0xD8, 0x92, 0x93, 0xC1, 0x9C, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x20
};
DWORD HalSendSMCMessageHook(LPVOID pRecvBuffer)
{
	memset(pRecvBuffer, 0x00, 0x10);
	memcpy(pRecvBuffer, spoofSMCKey, 0x5);
	return 0;
}

NTSTATUS GetSecurityInfo(XOSC_BUFFER* Response)
{
	HANDLE moduleHandle;
	WORD wvalue = 1;
	PLDR_DATA_TABLE_ENTRY pldr_dat;
	BYTE securityDigest[0x14];
	WORD unkwordt[8];
	BYTE smcResp[0x10];
	memset(unkwordt, 0, 16);
	unkwordt[7] = unkwordt[7] & 0xF8;

	Response->hvUnknown = 0;
	Response->secDataDvdBootFailures = 0;
	Response->kvRestrictedStatus = 0x00070000;
	Response->secDataFuseBlowFailures = 0;
	Response->secDataDvdAuthExFailures = 0;
	Response->secDataDvdAuthExTimeouts = 0;
	Response->kvRestrictedPrivs = 0;
	Response->hvSecurityDetected = 0;
	Response->hvSecurityActivated = 0;

	memcpy(securityDigest, (BYTE*)0x8E03AA40, 0x14);

	XECRYPT_SHA_STATE xamxSha;
	XeCryptShaInit(&xamxSha);
	memcpy(&xamxSha, xam_da, sizeof(XECRYPT_SHA_STATE));
	XeCryptShaUpdate(&xamxSha, securityDigest, 0x14);
	XeCryptShaUpdate(&xamxSha, (BYTE*)unkwordt, 0x10);
	XeCryptShaFinal(&xamxSha, securityDigest, 0x14);

	WORD unkword = 0;
	BYTE macaddress[6];

	if (NT_SUCCESS(ExGetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, macaddress, 6, &unkword)))
	{
		XECRYPT_SHA_STATE xkernelsha;
		XeCryptShaInit(&xkernelsha);
		memcpy(&xkernelsha, kernel_da, sizeof(XECRYPT_SHA_STATE));
		XeCryptShaUpdate(&xkernelsha, securityDigest, 0x14);
		XeCryptShaUpdate(&xkernelsha, (BYTE*)macaddress, 0x6);
		XeCryptShaFinal(&xkernelsha, securityDigest, 0x14);
		wvalue |= 2;
	}

	if (NT_SUCCESS(XexGetModuleHandle(NULL, &moduleHandle))) // NULL is = handle current title
	{
		PIMAGE_XEX_HEADER xheaders;
		pldr_dat = (PLDR_DATA_TABLE_ENTRY)moduleHandle;
		xheaders = (PIMAGE_XEX_HEADER)pldr_dat->XexHeaderBase;
		if (xheaders != NULL)
		{
			BYTE* bytetmp = (BYTE*)(xheaders->SecurityInfo + 0x17C);
			WORD wsize = xheaders->SizeOfHeaders - ((DWORD)bytetmp - (DWORD)xheaders);
			HalSendSMCMessageHook(smcResp);
			XEX_EXECUTION_ID* pExeId;
			XamGetExecutionId(&pExeId);

			if (pExeId->TitleID == 0xFFFE07D1 || pExeId->TitleID == 0xFFFF0055 || pExeId->TitleID == 0xC0DE9999 || pExeId->TitleID == 0xFFFE07FF || pExeId->TitleID == 0xF5D20000 || pExeId->TitleID == 0xFFFF011D || pExeId->TitleID == 0x00000166
				|| pExeId->TitleID == 0x00000189 || pExeId->TitleID == 0x00000188 || pExeId->TitleID == 0x00000176 || pExeId->TitleID == 0x00000167 || pExeId->TitleID == 0x00000177 || pExeId->TitleID == 0x00000170
				|| pExeId->TitleID == 0xFFFEFF43 || pExeId->TitleID == 0xFEEDC0DE || pExeId->TitleID == 0x00000001 || pExeId->TitleID == 0x00000171 || pExeId->TitleID == 0xFFED0707
				|| pExeId->TitleID == 0x00000000 || pExeId->TitleID == 0x1CED2911 || pExeId->TitleID == 0xFFED7300 || pExeId->TitleID == 0x00FBAFBA || pExeId->TitleID == 0x000003D0)
			{
				memcpy(Response->xexExecutionId, dashExid, 0x18);

				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				memcpy(&xsha, dash_da, sizeof(XECRYPT_SHA_STATE));
				XeCryptShaUpdate(&xsha, securityDigest, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaFinal(&xsha, securityDigest, 0x14);
			}
			else
			{
				XECRYPT_SHA_STATE xsha;
				XeCryptShaInit(&xsha);
				XeCryptShaUpdate(&xsha, bytetmp, wsize);
				XeCryptShaUpdate(&xsha, securityDigest, 0x14);
				XeCryptShaUpdate(&xsha, smcResp, 0x5);
				XeCryptShaFinal(&xsha, securityDigest, 0x14);
			}
			wvalue |= 4;
		}
	}
	XeCryptSha((PBYTE)0x900101A3, 0x8E59, securityDigest, 0x14, 0, 0, securityDigest, 0x14);
	securityDigest[0] = (unkwordt[7] | wvalue) & 0xFF;
	memcpy(Response->xexHashing, securityDigest, 0x10);
	memcpy(Response->zeroEncryptedConsoleType, (PVOID)0x8E03AA50, 0x10);
	return 0;
}
void NetDll_XnpLogonSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, PXOSC_BUFFER Response, DWORD bufferSize) {

}

typedef void(*tNetDll_XnpSetChallengeResponse)(XNCALLER_TYPE xnc, DWORD r4, PXOSC_BUFFER respBuff, DWORD respSize);
tNetDll_XnpSetChallengeResponse OriginalNetDll_XnpSetChallengeResponse;
void NetDll_XnpSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, PXOSC_BUFFER respBuff, DWORD respSize) {
	

	KEY_VAULT kv2;
	memset(respBuff, 0, respSize);
	memset(respBuff, 0xAA, 0x2E0);

	BYTE* KV = (BYTE*)XPhysicalAlloc(0x4000, MAXULONG_PTR, 0, PAGE_READWRITE);
	memcpy(KV, &kv2, 0x4000);

	XEX_EXECUTION_ID* ExecutionID;
	XamGetExecutionId(&ExecutionID);

	int HV_PROTECTED_FLAGS_NONE = 0;
	int HV_PROTECTED_FLAGS_NO_EJECT_REBOOT = 1;
	int HV_PROTECTED_FLAGS_AUTH_EX_CAP = 4;

	QWORD HvProtectedFlags = *(QWORD*)0x8E038678;
	QWORD HV_PROTECTED_FLAGS = HV_PROTECTED_FLAGS_AUTH_EX_CAP | (((HvProtectedFlags & HV_PROTECTED_FLAGS_NO_EJECT_REBOOT) == HV_PROTECTED_FLAGS_NO_EJECT_REBOOT) ? HV_PROTECTED_FLAGS_NO_EJECT_REBOOT : HV_PROTECTED_FLAGS_NONE);

	DWORD flash_size = *(DWORD*)(KV + 0x24);

	WORD BLDR_FLAGS = 0xD83E;
	WORD BLDR_FLAGS_KV1 = (~0x20);

	DWORD HvKeysStatusFlags = 0x023289D3;
	if (xbLive.bCRL) HvKeysStatusFlags |= 0x10000;
	if (xbLive.bFCRT) HvKeysStatusFlags |= 0x1000000;

	respBuff->dwResult = 0;
	respBuff->MajorVersion = 9;
	respBuff->MinorVersion = 2;
	respBuff->qwflags = 0x00000000000001BF;
	respBuff->DvdInqResp = 0;
	respBuff->XeikaInqResp = 0;
	respBuff->executionIdResponse = 0;
	respBuff->HvIdCacheDataResp = 0;
	respBuff->MediaInfoResp = 0xC8003003;
	respBuff->MediaInfodwUnk1 = 0xAAAAAAAA;
	respBuff->MediaInfodwUnk2 = 0xAAAAAAAA;
	respBuff->MediaInfoAbUnk = 0xAAAAAAAA;
	respBuff->MediaInfoPad5 = 0xAAAAAAAA;
	respBuff->HwMaskTemplate = 0x40000012;
	memcpy(respBuff->xexExecutionId, ExecutionID, 0x18);
	memcpy(respBuff->hvCpuKeyHash, CPUKeyDigest, 0x10);
	memset(respBuff->DvdXeikaPhaseLevel, 0, 0x3);
	respBuff->drivePhaseLevel = *(BYTE*)(KV + 0xC89);
	respBuff->dwMediaType = 0;
	respBuff->dwTitleId = 0;
	memset(respBuff->DvdPfiInfo, 0xAA, 0x11);
	memset(respBuff->DvdDmiMediaSerial, 0xAA, 0x20);
	memset(respBuff->DvdMediaId1, 0xAA, 0x10);
	memset(respBuff->abPad, 0xAA, 0x03);
	respBuff->DvdDmi10Data = 0xAAAAAAAAAAAAAAAA;
	respBuff->DvdGeometrySectors = 0xAAAAAAAA;
	respBuff->DvdGeometryBytesPerSector = 0xAAAAAAAA;
	memset(respBuff->DvdMediaId2, 0xAA, 0x10);
	memcpy(respBuff->DvdInqRespData, KV + 0xC8A, 0x24);
	memcpy(respBuff->XeikaInqData, KV + 0xC8A, 0x24);
	memcpy(respBuff->consoleSerial, KV + 0xB0, 0xC);
	respBuff->serialByte = 0x00AA;
	respBuff->hvHeaderFlags = (xbLive.bTypeOneKV == FALSE) ? ((WORD)(BLDR_FLAGS & BLDR_FLAGS_KV1)) : BLDR_FLAGS;
	respBuff->hvUnrestrictedPrivs = *(WORD*)(KV + 0xC8);
	respBuff->kvOddFeatures = *(WORD*)(KV + 0x1C);
	respBuff->kvPolicyFlashSize = flash_size;
	respBuff->hvKeyStatus = HvKeysStatusFlags;
	memset(&respBuff->dwPad1, 0xAA, 0x4);
	memset(&respBuff->dwPad2, 0xAA, 0x4);
	respBuff->HardwareMask = kvPcieFlag;
	respBuff->hvProtectedFlags = HV_PROTECTED_FLAGS;
	memcpy(respBuff->consoleId, KV + 0x9CA, 0x5);
	memset(respBuff->_unk14, 0, 0x2B);
	respBuff->XboxHardwareInfoFlags = kvHardwareFlag;
	memset(respBuff->HddSerialNumber, 0, 0x14);
	memset(respBuff->HddFirmwareRevision, 0, 0x08);
	memset(respBuff->HddModelNumber, 0, 0x28);
	memset(respBuff->HddUserAddressableSectors, 0, 0x04);
	memset(respBuff->unkMediaInfo, 0xAA, 0x80);
	respBuff->DvdUnkp1 = 0xAAAAAAAAAAAAAAAA;
	respBuff->MediaInfoUnkp3 = 0xAAAAAAAA;
	respBuff->MemoryUnit0 = 0;
	respBuff->MemoryUnit1 = 0;
	respBuff->InMuSfcAu = 0;
	respBuff->IntMuUSBAu = 0;
	respBuff->UsbMu0PartitionFileSize = 0x00020000;
	respBuff->UsbMu1PartitionFileSize = 0;
	respBuff->UsbMu2PartitionFileSize = 0;
	respBuff->crlVersion = 6;
	respBuff->Layer0PfiSectors = 0xAAAAAAAAAAAAAAAA;
	respBuff->Layer1PfiSectors = 0xAAAAAAAAAAAAAAAA;
	respBuff->respMagic = 0x5F534750;
	memset(&respBuff->dwFinalPad, 0xAA, 0x4);
	memset(&respBuff->NulledBuffer, 0, 0x120);

	GetSecurityInfo(respBuff);

	XPhysicalFree(KV);
	//SWriteFile("HDD:\\xosc_resp.bin", Response, bufferSize);
	//Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xosc_challenge_dirty_%i.bin", (int)time(0)), respBuff, 0x400);
	XNotifyQueueUI(XNOTIFYUI_TYPE_COMPLAINT, 0, 2, L"[XbLive] XOSC Success!", 0);
	//NetDll_XnpLogonSetChallengeResponseOriginal.callOriginal(xnc, r4, Response, bufferSize);
	OriginalNetDll_XnpSetChallengeResponse(xnc, r4, respBuff, respSize);
}

bool SystemHooks::XexCheckExecutablePrivilegeHook(int priviledge) {
	if (priviledge == 6) return true; // PRIV_INSECURE_SOCKS
	if (priviledge == 0x11) return false; // PRIV_AP25_MEDIA
	return XexCheckExecutablePrivilege(priviledge);
}

HRESULT SystemHooks::XexStartExecutableHook(FARPROC TitleProcessInitThreadProc) {
	auto res = XexStartExecutable(TitleProcessInitThreadProc);
	TitleHooks::RunOnTitleLoad((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	return res;
}

void SystemHooks::XSecurityCloseProcessHook() {
	return;
}

void SystemHooks::APCWorker(void* Arg1, void* Arg2, void* Arg3) {
	if (Arg2)
		((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
}

int SystemHooks::XSecurityCreateProcessHook(int dwHardwareThread) {
	return 0;
}

int SystemHooks::XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
	if (lpCompletionRoutine)
		NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);

	return ERROR_SUCCESS;
}

int SystemHooks::XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation) {
	if (pFailureInformation->dwSize != 0x18)
		return ERROR_NOT_ENOUGH_MEMORY;

	pFailureInformation->dwBlocksChecked = 0;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = 0;
	pFailureInformation->fComplete = TRUE;

	return ERROR_SUCCESS;
}

int SystemHooks::XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress) {
	if (hand == GetModuleHandleA(MODULE_XAM)) {
		switch (dwOrdinal) {
		case 0x9BB:
			*pvAddress = XSecurityCreateProcessHook;
			return 0;
		case 0x9BC:
			*pvAddress = XSecurityCloseProcessHook;
			return 0;
		case 0x9BD:
			*pvAddress = XSecurityVerifyHook;
			return 0;
		case 0x9BE:
			*pvAddress = XSecurityGetFailureInfoHook;
			return 0;
		}
	}

	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

void* SystemHooks::RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey) {
	void* retVal = RtlImageXexHeaderField(headerBase, imageKey);

	if (imageKey == 0x40006 && retVal) {
		switch (((XEX_EXECUTION_ID*)retVal)->TitleID) {
		case 0xFFFF0055:   // Xex Menu
		case 0xFFFE07FF:   // XShellXDK
		case 0xF5D10000:   // dl main
		case 0xFFFF011D:   // dl installer
		case 0xF5D20000:   // fsd
		case 0x00000195:   // XeBoy Advance
		case 0x1CED291:    // PlayStation 1
		case 0x00000174:   // MAME360
		case 0x00000177:   // NXE2GOD
		case 0x00000180:   // DosBox
		case 0x00000167:   // Freestyle 3
		case 0x00000176:   // XM360
		case 0x00000184:   // OpenBOR360
		case 0xFFED7301:   // GameBoyAdvance360
		case 0x00001039:   // Snes360 PAL simpel v1
		case 0xFFED0707:   // Snes360
		case 0xFFFF051F:   // Atari 2600
		case 0x00000178:   // SuperMarioWar
		case 0x00000170:   // XexMenu 2.0
		case 0x00000166:   // Aurora
		case 0x4D5707DB:   // Unreal dev engine
		case 0x584b87ff:   // 360dashit
		case 0x00000155:   // psx emulator (early version)
		case 0x1CED2911: {  // psx emulator
			int ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (KERNEL_VERSION << 8) | (XboxKrnlVersion->Qfe);
			xbLive.ExecutionIDSpoof.BaseVersion = ver;
			xbLive.ExecutionIDSpoof.Version = ver;
			memcpy(retVal, &xbLive.ExecutionIDSpoof, sizeof(XEX_EXECUTION_ID));
			break;
		}
		}
	} else if (imageKey == 0x40006 && !retVal) {
		retVal = &xbLive.ExecutionIDSpoof;
	}

	return retVal;
}
typedef void(*tXNotifyQueueUI)(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam);
tXNotifyQueueUI OriginalXNotifyQueueUI;
void SystemHooks::XNotifyQueueUIHook(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam) {
	if (xbLive.bCanNotify) {
		OriginalXNotifyQueueUI(dwType, dwUserIndex, dwPriority, pwszStringParam, qwParam);
	} else {
		if (Notify::Bypass[pwszStringParam]) {
			OriginalXNotifyQueueUI(dwType, dwUserIndex, dwPriority, pwszStringParam, qwParam);
		} else {
			Notify((wchar_t*)pwszStringParam).HookFix(dwType, dwUserIndex, dwPriority, qwParam);
		}
	}
}

typedef int(*tNetDll_connect)(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length);
tNetDll_connect OriginalNetDll_connect;
int SystemHooks::NetDll_connectHook(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length) {
	if (name) {
		sockaddr_in* ptr = (sockaddr_in*)name;
		if (ptr) {
			if (ptr->sin_addr.S_un.S_addr == 0x69696969) {
#ifdef LOCAL_SERVER
				ptr->sin_addr.S_un.S_un_b.s_b1 = 192;
				ptr->sin_addr.S_un.S_un_b.s_b2 = 168;
				ptr->sin_addr.S_un.S_un_b.s_b3 = 0;
				ptr->sin_addr.S_un.S_un_b.s_b4 = 23;
#else



				ptr->sin_addr.S_un.S_un_b.s_b1 = 207;
				ptr->sin_addr.S_un.S_un_b.s_b2 = 45;
				ptr->sin_addr.S_un.S_un_b.s_b3 = 82;
				ptr->sin_addr.S_un.S_un_b.s_b4 = 102;

				//ptr->sin_addr.S_un.S_un_b.s_b1 = (u_char)Native::DecryptDWORD(0x8DFBD /*34*/); 
				//ptr->sin_addr.S_un.S_un_b.s_b2 = (u_char)Native::DecryptDWORD(0x8E11F /*76*/); 
				//ptr->sin_addr.S_un.S_un_b.s_b3 = (u_char)Native::DecryptDWORD(0x8E3E4 /*153*/);
				//ptr->sin_addr.S_un.S_un_b.s_b4 = (u_char)Native::DecryptDWORD(0x8E40C /*145*/);

#endif
			}
		}
	}

	return OriginalNetDll_connect(xnCaller, socket, name, length);
}

typedef DWORD(*tXamShowMessageBoxUI)(DWORD dwUserIndex, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, DWORD dwFlags, PMESSAGEBOX_RESULT pResult, PXOVERLAPPED pOverlapped);
tXamShowMessageBoxUI OriginalXamShowMessageUI;
DWORD SystemHooks::XamShowMessageBoxUIHook(DWORD dwUserIndex, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, DWORD dwFlags, PMESSAGEBOX_RESULT pResult, PXOVERLAPPED pOverlapped) {
	if (wszText) {
		bool valid = false;
		if (wcsstr(wszText, L"Status Code: 807b0190")) {
			valid = true;
			wszText = L"We broke the store! Sorry about that :( We aim to have it fixed real soon.";
		} else if (wcsstr(wszText, L"80151907")) {
			valid = true;
			wszText = L"We got a bad response from Live, most likely related to your KV.";
		} else if (wcsstr(wszText, L"8015190E") || wcsstr(wszText, L"83859DD2")) {
			valid = true;
			wszText = L"You're temporarily blocked from connecting to Xbox Live! Please turn off your console for at least 5 minutes, then try again.";
			Launch::SetLiveBlock(true);
		} else if (wcsstr(wszText, L"8015000A")) {
			valid = true;
			wszText = L"You've got an error, 8015000A. This is most common when using a bridged connection to connect your console to the internet. If this is the case for you, reset your network adapter config.";
		}

		if (valid) {
			pwszButtons = new const wchar_t*[1];
			pwszButtons[0] = new wchar_t[6];
			lstrcpyW((wchar_t*)pwszButtons[0], L"Okay!");

			return OriginalXamShowMessageUI(dwUserIndex, wszTitle, wszText, 1, pwszButtons, dwFocusButton, dwFlags, pResult, pOverlapped);
		}
	}

	return OriginalXamShowMessageUI(dwUserIndex, wszTitle, wszText, cButtons, pwszButtons, dwFocusButton, dwFlags, pResult, pOverlapped);
}

typedef HRESULT(*tXamShowMessageBox)(DWORD unk, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, MBOXRESULT resFun, DWORD dwFlags);
tXamShowMessageBox OriginalXamShowMessageBox;
HRESULT SystemHooks::XamShowMessageBoxHook(DWORD unk, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, MBOXRESULT resFun, DWORD dwFlags) {
	if (wszText) {
		bool valid = false;
		if (wcsstr(wszText, L"Status Code: 807b0190")) {
			valid = true;
			wszText = L"We broke the store! Sorry about that :( We aim to have it fixed real soon.";
		} else if (wcsstr(wszText, L"80151907")) {
			valid = true;
			wszText = L"We got a bad response from Live, most likely related to your KV.";
		} else if (wcsstr(wszText, L"8015190E") || wcsstr(wszText, L"83859DD2")) {
			valid = true;
			wszText = L"You're temporarily blocked from connecting to Xbox Live! Please turn off your console for at least 5 minutes, then try again.";
			Launch::SetLiveBlock(true);
		} else if (wcsstr(wszText, L"8015000A")) {
			valid = true;
			wszText = L"You've got an error, 8015000A. This is most common when using a bridged connection to connect your console to the internet. If this is the case for you, reset your network adapter config.";
		}

		if (valid) {
			pwszButtons = new const wchar_t*[1];
			pwszButtons[0] = new wchar_t[6];
			lstrcpyW((wchar_t*)pwszButtons[0], L"Okay!");

			return OriginalXamShowMessageBox(unk, wszTitle, wszText, 1, pwszButtons, dwFocusButton, resFun, dwFlags);
		}
	}

	return OriginalXamShowMessageBox(unk, wszTitle, wszText, cButtons, pwszButtons, dwFocusButton, resFun, dwFlags);
}

typedef void*(*tXexPcToFileHeader)(DWORD, PLDR_DATA_TABLE_ENTRY*);
tXexPcToFileHeader OriginalXexPcToFileHeader;
void* SystemHooks::XexPcToFileHeaderHook(DWORD pAddress, PLDR_DATA_TABLE_ENTRY* ldatOut) {
	DWORD dwLR = 0;
	__asm mflr dwLR

	if (dwLR > 0x91C10000 && dwLR < 0x91D10000 && pAddress) {
		if (*(BYTE*)(pAddress) == 'x') {
			// cheat load
			DWORD hiddenThreadStartup = *(DWORD*)(pAddress + 4);
			if (hiddenThreadStartup) {
				Invoke::Call<DWORD>(hiddenThreadStartup);
				if (ldatOut) *ldatOut = nullptr;
				return nullptr;
			}
		}
	}

	return OriginalXexPcToFileHeader(pAddress, ldatOut);
}

typedef HRESULT(*tThreadProcServiceSystemTasks)(PVOID pvParam);
tThreadProcServiceSystemTasks OriginalThreadProcServiceSystemTasks;
HRESULT ThreadProcServiceSystemTasksHook(PVOID pvParam) {
	static int counter = 0;
	while (xbLive.dwNoKVHash == 0) {
		Sleep(10);

		if (xbLive.bLoadedProperly)
			counter++;

		// 20s timeout
		if (counter > 2000) {
			Config::bUsingNoKV = false;
			if (xbLive.bHasTime) {
				Notify(StrEnc("xbLive - Failed to get server KV")).Message();
			}
			break;
		}
	}

	Hooking::Unhook(xbLive.Address->dwThreadProcServiceSystemTasks);

	LOG_DEV("Allowing XOnline to initialize...");
	return OriginalThreadProcServiceSystemTasks(pvParam);
}

typedef NTSTATUS(*tKerbAddConsoleCertHashPrePreAuth)(DWORD, BYTE*, DWORD);
tKerbAddConsoleCertHashPrePreAuth OriginalKerbAddConsoleCertHashPrePreAuth;
NTSTATUS KerbAddConsoleCertHashPrePreAuthHook(DWORD r3, BYTE* cert, DWORD r5) {
	if (xbLive.dwNoKVHash != 0x0) {
		if (cert) {
			BYTE decryptedCert[0x1A8];
		
			memcpy(decryptedCert, xbLive.szNoKVConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
			BYTE rc4Key[34] = { // "plz don't steal and ban kv, is sin"
				0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74, 0x65,
				0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20, 0x6B, 0x76,
				0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
			};
			Native::XeCryptRc4(rc4Key, sizeof(rc4Key), decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
	
			memcpy(cert, decryptedCert, Native::DecryptDWORD(0x8E443 /*0x1A8*/));
		}
	}

	return OriginalKerbAddConsoleCertHashPrePreAuth(r3, cert, r5);
}

typedef NTSTATUS(*tXeKeysGetConsoleCertificate)(BYTE*);
tXeKeysGetConsoleCertificate OriginalXeKeysGetConsoleCertificate;
NTSTATUS XeKeysGetConsoleCertificateHook(BYTE* cert) {
	if (xbLive.dwNoKVHash != 0x0) {
		if (cert) {
			BYTE decryptedCert[0x1A8];

			memcpy(decryptedCert, xbLive.szNoKVConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
					
			BYTE rc4Key[34] = { // "plz don't steal and ban kv, is sin"
				0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74, 0x65,
				0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20, 0x6B, 0x76,
				0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
			};
			Native::XeCryptRc4(rc4Key, sizeof(rc4Key), decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
			memcpy(cert, decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));

			return ERROR_SUCCESS;
		}
	}

	return OriginalXeKeysGetConsoleCertificate(cert);
}

typedef void(*tFormatXenonConsoleCertificatePrincipalName)(DWORD, char*, DWORD);
tFormatXenonConsoleCertificatePrincipalName OriginalFormatXenonConsoleCertificatePrincipalName;
void FormatXenonConsoleCertificatePrincipalNameHook(DWORD r3, char* r4, DWORD r5) {
	if (xbLive.dwNoKVHash != 0x0) {
		char* str = r4;
		str[0] = 0x58; // X
		str[1] = 0x45; // E
		str[2] = 0x2E; // .
		str += 3;

		BYTE decryptedCert[0x1A8];
		memcpy(decryptedCert, xbLive.szNoKVConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
		BYTE rc4Key[34] = { // "plz don't steal and ban kv, is sin"
			0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74, 0x65,
			0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20, 0x6B, 0x76,
			0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
		};
		Native::XeCryptRc4(rc4Key, sizeof(rc4Key), decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));

		unsigned long long r11 = 0;
		for (int i = 0; i < 5; i++) {
			BYTE r9 = *(BYTE*)(decryptedCert + 2 + i);
			r11 = r11 << 8;
			r11 = r9 + r11;
		}

		_snprintf(str, r5, StrEnc("%011I64u%u"), r11 >> 4, r11 & 0xFFFFFFFF & 0xF);

		if (xbLive.bDevkit) {
			DWORD firstArg = *(DWORD*)(r3 + Native::DecryptDWORD(0x91023 /*0x2D48*/));
			DWORD ret = 0;

			__asm rlwinm ret, firstArg, 0, 13, 13

			if (ret == 0) {
				str[0xC] = 0x0;
			} else {
				str[r5 - 1] = -1;
			}
		} else {
			str[0xF] = 0x0;
		}

		return;
	}

	return OriginalFormatXenonConsoleCertificatePrincipalName(r3, r4, r5);
}

typedef NTSTATUS(*tGetSerialNumber)(DWORD, BYTE*);
tGetSerialNumber OriginalGetSerialNumber;
NTSTATUS GetSerialNumberHook(DWORD r3, BYTE* outSerial) {
	if (xbLive.dwNoKVHash != 0x0) {
		memcpy(outSerial, xbLive.szNoKVSerial, Native::DecryptDWORD(0x8E15F /*0xC*/));
		return ERROR_SUCCESS;
	}

	return OriginalGetSerialNumber(r3, outSerial);
}
DWORD UpdateSequence = 0x00000008;
DWORD HVSF() {
	DWORD HV_STATUS_FLAG = 0x023289D3;
	HV_STATUS_FLAG = (xbLive.bCRL == 1) ? (HV_STATUS_FLAG | 0x10000) : HV_STATUS_FLAG;
	HV_STATUS_FLAG = (xbLive.bFCRT == 1) ? (HV_STATUS_FLAG | 0x1000000) : HV_STATUS_FLAG;
	return HV_STATUS_FLAG;
}
VOID FillBuffer(PVOID pvPhyBuffer, DWORD len, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4)
{
	return VOID();
}
long long SystemHooks::XeKeysExecuteHook(XE_KEYS_BUFFER* buffer, int fileSize, byte* salt, long long input2, long long input3, long long input4) {

	WORD BLDR_FLAGS = 0xD83E;
	WORD BLDR_FLAGS_KV1 = (~0x20);
	*(DWORD*)0x80108520 = 0x38000042;
	*(DWORD*)0x80108524 = 0x44000002;
	*(DWORD*)0x80108528 = 0x4E800020;
	BYTE* consoleHv = (BYTE*)XPhysicalAlloc(0x40000, MAXULONG_PTR, 0, PAGE_READWRITE);
	Hypervisor::HvPeekBytes(0x8000010000000000, consoleHv, 0x10000);
	Hypervisor::HvPeekBytes(0x8000010200010000, consoleHv + 0x10000, 0x10000);
	Hypervisor::HvPeekBytes(0x8000010400020000, consoleHv + 0x20000, 0x10000);
	Hypervisor::HvPeekBytes(0x8000010600030000, consoleHv + 0x30000, 0x10000);
	*(WORD*)(cleanHv + 0x6) = (xbLive.bTypeOneKV == FALSE) ? ((WORD)(BLDR_FLAGS & BLDR_FLAGS_KV1)) : BLDR_FLAGS;
	*(DWORD*)(cleanHv + 0x14) = UpdateSequence;
	*(DWORD*)(cleanHv + 0x30) = HVSF();
	*(DWORD*)(cleanHv + 0x74) = kvCbFlag;

	memcpy(cleanHv + 0x20, consoleHv + 0x20, 0x10);
	memcpy(cleanHv + 0x10000, consoleHv + 0x10000, 0xC0);
	memcpy(cleanHv + 0x10100, consoleHv + 0x10100, 0x30);
	memcpy(cleanHv + 0x16390, consoleHv + 0x16390, 0x04);
	memcpy(cleanHv + 0x16620, consoleHv + 0x16620, 0x01);
	memcpy(cleanHv + 0x16640, consoleHv + 0x16640, 0x14);
	memcpy(cleanHv + 0x16710, consoleHv + 0x16710, 0x10);
	memcpy(cleanHv + 0x16980, consoleHv + 0x16980, 0x102);
	memcpy(cleanHv + 0x16B90, consoleHv + 0x16B90, 0x10);
	memcpy(cleanHv + 0x16E98, consoleHv + 0x16E98, 0x4);

	Hypervisor::HvPokeBytes(0x8000010000000000, cleanHv, 0x10000);
	Hypervisor::HvPokeBytes(0x8000010200010000, cleanHv + 0x10000, 0x10000);
	Hypervisor::HvPokeBytes(0x8000010400020000, cleanHv + 0x20000, 0x10000);
	Hypervisor::HvPokeBytes(0x8000010600030000, cleanHv + 0x30000, 0x10000);

	xeKeysExecute((BYTE*)buffer, (DWORD)fileSize, (PVOID)MmGetPhysicalAddress(salt), (QWORD*)0x0002000044970000, 0, 0);
	
	*(DWORD*)(buffer + 0x30) = 0x07600000;
	*(QWORD*)(buffer + 0x40) = 0x0000000200000000;
	*(QWORD*)(buffer + 0x48) = 0x0000010000000000;
	memcpy(buffer + 0x64, CPUKeyDigest, 0x14);
	Hypervisor::HvPokeBytes(0x8000010000000000, consoleHv, 0x10000);
	Hypervisor::HvPokeBytes(0x8000010200010000, consoleHv + 0x10000, 0x10000);
	Hypervisor::HvPokeBytes(0x8000010400020000, consoleHv + 0x20000, 0x10000);
	Hypervisor::HvPokeBytes(0x8000010600030000, consoleHv + 0x30000, 0x10000);
	XPhysicalFree(consoleHv);
	!xbLive.bCRL ? Notify(StrEnc("[XbLive] Connecting to Live!")).Message(), xbLive.bCRL = TRUE : NULL;
	Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\XKE_resp_%i.bin", (int)time(0)), buffer, 0x400);
	return 0;
}

HRESULT SystemHooks::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	/*int ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (KERNEL_VERSION << 8) | (XboxKrnlVersion->Qfe);
	memset(&xbLive.ExecutionIDSpoof, 0, sizeof(XEX_EXECUTION_ID));
	xbLive.ExecutionIDSpoof.Version = ver;
	xbLive.ExecutionIDSpoof.BaseVersion = ver;
	xbLive.ExecutionIDSpoof.TitleID = 0xFFFE07D1;*/

	if (Config::bUsingNoKV) {
		//Hooking::HookFunction(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E192 /*31*/)), &XeKeysGetConsoleCertificateHook, &OriginalXeKeysGetConsoleCertificate, true);
		//Hooking::HookFunction(xbLive.Address->dwThreadProcServiceSystemTasks, &ThreadProcServiceSystemTasksHook, &OriginalThreadProcServiceSystemTasks);
		//Hooking::HookFunction(xbLive.Address->dwKerbAddConsoleCertHashPrePreAuth, &KerbAddConsoleCertHashPrePreAuthHook, &OriginalKerbAddConsoleCertHashPrePreAuth, true);
		//Hooking::HookFunction(xbLive.Address->dwFormatXenonConsoleCertificatePrincipalName, &FormatXenonConsoleCertificatePrincipalNameHook, &OriginalFormatXenonConsoleCertificatePrincipalName, true);
		//Hooking::HookFunction(xbLive.Address->dwGetSerialNumber, &GetSerialNumberHook, &OriginalGetSerialNumber, true);
	}

	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E3EB /*128*/)), &NetDll_XnpSetChallengeResponseHook, &OriginalNetDll_XnpSetChallengeResponse, true);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E61B /*656*/)), &XNotifyQueueUIHook, &OriginalXNotifyQueueUI);
	//Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E15F /*12*/)), &NetDll_connectHook, &OriginalNetDll_connect, true);


	//Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E5B5 /*714*/)), &XamShowMessageBoxUIHook, &OriginalXamShowMessageUI);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E614 /*745*/)), &XamShowMessageBoxHook, &OriginalXamShowMessageBox);
	
	
	Hooking::HookFunction(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E70F /*412*/)), &XexPcToFileHeaderHook, &OriginalXexPcToFileHeader);

	Launch::SetLiveBlock(false);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8EB52 /*607*/), XeKeysExecuteHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E74B /*416*/), XexStartExecutableHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E757 /*404*/), XexCheckExecutablePrivilegeHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E71A /*407*/), XexGetProcedureAddressHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E6D6 /*299*/), RtlImageXexHeaderFieldHook);


	IntegrityManager::Push(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8EB52 /*607*/)), 16, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x2080ac71));

	// xshell creation
	if (xbLive.bDevkit) {
		*(DWORD*)xbLive.Address->dwXShell[0] = 0x60000000;

		wchar_t buffer[15];
		lstrcpyW(buffer, L"%s@");
		lstrcatW(buffer, Utils::vaw(Config::szXShellEmail));

		lstrcpyW((wchar_t*)xbLive.Address->dwXShell[1], buffer);
		lstrcpyW((wchar_t*)xbLive.Address->dwXShell[2], Utils::vaw(Config::szXShellPassword));

		char buffer2[16];
		strcpy(buffer2, StrEnc("%ws@"));
		strcat(buffer2, Config::szXShellEmail);

		strcpy((char*)xbLive.Address->dwXShell[3], buffer2);
		strcpy((char*)xbLive.Address->dwXShell[4], Utils::va(StrEnc("@%s"), Config::szXShellEmail));
		strcpy((char*)xbLive.Address->dwXShell[5], Config::szXShellPassword);
	}

	ENCRYPTION_MARKER_END;
	return S_OK;
}