#pragma once

#define KEYVAULT_HV_PTR xbLive.bDevkit ? 0x00000002000162e0 : 0x00000002000163C0

class Keyvault {
public:
	static HRESULT Initialize();
	static HRESULT SetKeyvault(BYTE* pBuffer, bool reboot = true);
	static int GetMotherboardIndex();
	static KEY_VAULT* GetKeyVault() { return (KEY_VAULT*)szKV; }
	static BYTE* GetKeyvaultDigest() { return szKVDigest; }
	static DWORD GetKeyvaultHash();
private:
	static bool bInitializedKVHash;
	static BYTE szKV[0x4000];
	static BYTE szKVDigest[0x10];
	static BYTE szKVHash[0x10];
};
extern BYTE CPUKeyDigest[0x14];
extern DWORD kvCbFlag;
extern DWORD kvHardwareFlag;
extern QWORD kvPcieFlag;
extern DWORD dwUpdateSequence;
extern BYTE kvFuseKey[0xC];
extern BYTE spoofSMCKey[0x5];
extern BYTE coronaKey[0xC];
extern BYTE falconKey[0xC];
extern BYTE jasperKey[0xC];
extern BYTE trinityKey[0xC];
extern BYTE zephyrKey[0xC];
extern BYTE xenonKey[0xC];
extern BYTE coronaSMC[5];
extern BYTE trinitySMC[5];
extern BYTE jasperSMC[5];
extern BYTE falconSMC[5];
extern BYTE zephyrSMC[5];
extern BYTE xenonSMC[5];