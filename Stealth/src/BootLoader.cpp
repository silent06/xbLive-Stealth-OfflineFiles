#include "stdafx.h"
BYTE SignRSA_Pub[0x90] = {
	0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0xD0, 0x55, 0x50, 0x79, 0x19, 0x95, 0x27,
	0x78, 0x89, 0x97, 0x08, 0xDE, 0x24, 0xD1, 0xED, 0xB1, 0xEA, 0xE5, 0x48,
	0xAC, 0x1A, 0xC3, 0xC8, 0x29, 0x45, 0xB0, 0x16, 0x9B, 0xEF, 0x78, 0x8F,
	0xEF, 0x26, 0x9D, 0x54, 0x59, 0x95, 0x2D, 0x25, 0xA5, 0xAC, 0xA3, 0xA6,
	0x94, 0x45, 0xE5, 0x42, 0x2E, 0x39, 0x88, 0x0C, 0x3C, 0xAE, 0xEB, 0xFD,
	0x53, 0x3A, 0xE9, 0x70, 0x43, 0xEA, 0xD1, 0xD1, 0x78, 0xCE, 0xED, 0x1C,
	0xE5, 0xFD, 0x0F, 0x80, 0x94, 0x6F, 0x4F, 0xFF, 0xAD, 0x45, 0x88, 0xCF,
	0x22, 0x4C, 0x56, 0xDE, 0x03, 0xE2, 0x46, 0x2F, 0x19, 0xB8, 0x2C, 0xD0,
	0xD7, 0xE9, 0x64, 0xB2, 0x68, 0x0C, 0x40, 0xF5, 0x4F, 0xDA, 0x80, 0x8F,
	0x71, 0xA9, 0x64, 0xA4, 0x15, 0x53, 0x6E, 0x2B, 0x49, 0x44, 0x55, 0xCB,
	0x05, 0x17, 0x3F, 0x66, 0xE1, 0x32, 0x2F, 0x1D, 0xE9, 0x2A, 0xD6, 0x4B
};
void ReverseRSA(PBYTE pbData, DWORD cbData) {
	DWORD dwMidpoint = cbData >> 1;
	DWORD dwReverseCounter = 0;
	PBYTE pbPtr = pbData;

	if (dwMidpoint) {
		while (dwReverseCounter < dwMidpoint) {
			DWORD i = (cbData - dwReverseCounter) - 1 & 0xFFFFFFFF;

			BYTE b1 = *pbPtr;
			BYTE b2 = pbData[i];
			*pbPtr = b2;
			pbData[i] = b1;

			dwReverseCounter++;
			pbPtr++;
		}
	}
}
void HvSetupShaSaltedHash(PBYTE Buffer1, DWORD Size1, PBYTE Buffer2, DWORD Size2) {
	DWORD i = 0;
	for (DWORD s = 0; s < Size2; s += 0x14)
	{
		DWORD subsize = (s + 0x14 > Size2) ? Size2 - s : 0x14;
		BYTE tmp[0x14];
		BYTE tmpint[] = { 0, 0, 0, i };

		XECRYPT_SHA_STATE sha;
		XeCryptShaInit(&sha);
		XeCryptShaUpdate(&sha, Buffer1, Size1);
		XeCryptShaUpdate(&sha, tmpint, 4);
		XeCryptShaFinal(&sha, tmp, 0x14);

		for (DWORD l = 0; l < subsize; l++)
		{
			Buffer2[s + l] ^= tmp[l];
		}
		i++;
	}
}
void HvSetupMemEncryptionKey(PBYTE Signature, PBYTE Key, PBYTE Random)
{
	BYTE ZeroSha[] = { 0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09 };
	memset(Signature, 0, 0x80);
	Signature[0] = 0;
	memcpy((Signature + 1), Random, 0x14);
	memcpy((Signature + 0x15), ZeroSha, 0x14);
	memset((Signature + 0x29), 0, 0x26);
	Signature[0x4F] = 1;
	memcpy((Signature + 0x50), Key, 0x30);
	HvSetupShaSaltedHash(Random, 0x14, (Signature + 0x15), 0x6B);
	HvSetupShaSaltedHash((Signature + 0x15), 0x6B, (Signature + 1), 0x14);
}
void sub_2440()
{
	BYTE Signature[0x80];
	BYTE shaSalt[0x14];
	BYTE Hv10100[0x30];

	Hypervisor::HvPeekBytes(0x8000010200010100, Hv10100, 0x30);
	XeCryptRandom(shaSalt, 0x14);
	HvSetupMemEncryptionKey(Signature, Hv10100, shaSalt);
	ReverseRSA(Signature, 0x80);
	XeCryptBnQw_SwapDwQwLeBe((PQWORD)Signature, (PQWORD)Signature, 0x10);
	XeCryptBnQwNeRsaPubCrypt((PQWORD)Signature, (PQWORD)Signature, (PXECRYPT_RSA)SignRSA_Pub);
	XeCryptBnQw_SwapDwQwLeBe((PQWORD)Signature, (PQWORD)Signature, 0x10);
	Hypervisor::HvPokeBytes(0x8000010200010040, Signature, 0x80);
}
HRESULT BootloaderHV() {
	LOG_PRINT(StrEnc("Running BootLoader!"));
	BYTE BootLoader_Key[0x10] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
	Hypervisor::HvPokeBytes(0x8000010200016510, BootLoader_Key, 0x10);
	BYTE szHvxKeysExecuteSyscall[0x04] = { 0x00, 0x00, 0x08, 0x22 };
	Hypervisor::HvPokeBytes(0x8000010200015F60, szHvxKeysExecuteSyscall, 0x04);
	BYTE szHvxKeysExecutePrologue[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x00, 0x48, 0x71, 0xF8, 0x21, 0xFC, 0xD1, 0x3D, 0x62, 0x00, 0x01 };
	Hypervisor::HvPokeBytes(0x8000010000005F68, szHvxKeysExecutePrologue, 0x10);
	BYTE szHvxExpansionInstallSyscall[0x04] = { 0x00, 0x00, 0xB2, 0xE0 };
	Hypervisor::HvPokeBytes(0x8000010200016020, szHvxExpansionInstallSyscall, 0x04);
	BYTE szHvxExpansionInstallPrologue[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x00, 0xA8, 0x07, 0xF8, 0x21, 0xFD, 0xF1, 0x3D, 0x62, 0x00, 0x01 };
	Hypervisor::HvPokeBytes(0x8000010600030710, szHvxExpansionInstallPrologue, 0x10);
	BYTE szHvxExpansionCallSyscall[0x04] = { 0x00, 0x00, 0xB2, 0x58 };
	Hypervisor::HvPokeBytes(0x8000010200016024, szHvxExpansionCallSyscall, 0x04);
	BYTE szHvxExpansionCallPrologue[0x10] = { 0x3D, 0x62, 0x00, 0x01, 0x39, 0x40, 0x00, 0x00, 0xE9, 0x6B, 0x6A, 0xD8, 0x39, 0x6B, 0x04, 0x00 };
	Hypervisor::HvPokeBytes(0x8000010600030970, szHvxExpansionCallPrologue, 0x10);
	sub_2440();
	return S_OK;
}