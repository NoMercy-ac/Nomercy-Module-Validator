#include <windows.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <iostream>
#include "../include/lazy_importer.hpp"
#include "../include/xorstr.hpp"
#include "../include/JunkMacros.h"

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define DEBUG_MODE 0

enum ELogLevels : uint8_t
{
	LL_SYS,
	LL_ERR,
	LL_CRI,
	LL_WARN,
	LL_DEV,
	LL_TRACE
};
static void APP_TRACE_LOG_EX(int, const wchar_t* c_wszFormat, ...)
{
#if (DEBUG_MODE == 1)
	va_list vaArgList;
	va_start(vaArgList, c_wszFormat);

	static auto s_cbBufferSize = 0x1000;

	const auto dwFormatSize = _vscwprintf(c_wszFormat, vaArgList) + 1;
	if (dwFormatSize > s_cbBufferSize)
	{
		s_cbBufferSize = dwFormatSize + 0x100;
	}

	const auto lpwszBuffer = static_cast<wchar_t*>(std::calloc(s_cbBufferSize, sizeof(wchar_t)));
	if (!lpwszBuffer)
	{
		const auto err = errno;
		wsprintfW(lpwszBuffer, xorstr_(L"Memory allocation failed for log operation! Last error: %u"), err);

		std::abort();
	}

	const auto cbBufferLength = _vsnwprintf_s(lpwszBuffer, s_cbBufferSize, s_cbBufferSize - 1, c_wszFormat, vaArgList);
	if (cbBufferLength < 0)
	{
		const auto err = errno;
		wsprintfW(lpwszBuffer, xorstr_(L"_vsnprintf_s returned with negative value. Last error: %u Length: %d Buffer: %s"), err, cbBufferLength, c_wszFormat);

		std::free(lpwszBuffer);
		return;
	}

	va_end(vaArgList);

	OutputDebugStringW(lpwszBuffer);
	std::wcout << lpwszBuffer << std::endl;

	std::free(lpwszBuffer);
#endif
}
#define APP_TRACE_LOG(level, format, ...) APP_TRACE_LOG_EX(level, xorstr_(format), __VA_ARGS__)

static std::wstring getCertificateProvider(HANDLE hWVTStateData)
{
	const auto pCryptProvData = WTHelperProvDataFromStateData(hWVTStateData);
	if (!pCryptProvData)
	{
		const auto dwError = GetLastError();
		if (dwError != TRUST_E_SUBJECT_NOT_TRUSTED)
		{
			APP_TRACE_LOG(LL_WARN, L"WTHelperProvDataFromStateData (1) failed with error: %u (%p)", hWVTStateData, dwError, dwError);
		}
		return {};
	}

	const auto pSigner = WTHelperGetProvSignerFromChain(pCryptProvData, 0, FALSE, 0);
	if (!pSigner)
	{
		APP_TRACE_LOG(LL_ERR, L"WTHelperGetProvSignerFromChain failed with error: %u (%p)", GetLastError(), GetLastError());
		return {};
	}

	const auto pCert = WTHelperGetProvCertFromChain(pSigner, 0);
	if (!pCert)
	{
		APP_TRACE_LOG(LL_ERR, L"WTHelperGetProvCertFromChain failed with error: %u", GetLastError());
		return {};
	}

	const auto dwRequiredSize = CertGetNameStringW(pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if (dwRequiredSize == 0)
	{
		APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW (1) failed with error: %u", GetLastError());
		return {};
	}

	std::wstring wstProvider = std::wstring(dwRequiredSize, L'\0');
	if (!CertGetNameStringW(pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, (wchar_t*)wstProvider.data(), (DWORD)wstProvider.size()))
	{
		APP_TRACE_LOG(LL_ERR, L"CertGetNameStringW (2) failed with error: %u", GetLastError());
		return {};
	}

	wstProvider.resize(wstProvider.size() - 1);
	return wstProvider;
}

static DWORD getSignerInfo(std::wstring aFileName, std::shared_ptr <CMSG_SIGNER_INFO>& aSignerInfo, HCERTSTORE& aCertStore)
{
	BOOL lRetVal = TRUE;

	DWORD lEncoding = 0;
	DWORD lContentType = 0;
	DWORD lFormatType = 0;
	HCERTSTORE lStoreHandle = nullptr;
	HCRYPTMSG lCryptMsgHandle = nullptr;
	lRetVal = CryptQueryObject(
		CERT_QUERY_OBJECT_FILE, aFileName.data(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&lEncoding, &lContentType, &lFormatType, &lStoreHandle, &lCryptMsgHandle, NULL
	);
	if (!lRetVal)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"CryptQueryObject failed with error: %u/%p", dwErrorCode, dwErrorCode);
		return dwErrorCode;
	}

	DWORD lSignerInfoSize = 0;
	lRetVal = CryptMsgGetParam(lCryptMsgHandle, CMSG_SIGNER_INFO_PARAM, 0, NULL, &lSignerInfoSize);
	if (!lRetVal)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"CryptMsgGetParam(1) failed with error: %u", dwErrorCode);
		return dwErrorCode;
	}

	auto lSignerInfoPtr = (PCMSG_SIGNER_INFO)new BYTE[lSignerInfoSize];
	if (!lSignerInfoPtr)
	{
		const auto dwErrorCode = errno;
		APP_TRACE_LOG(LL_ERR, L"Memory allocation failed with error: %u", dwErrorCode);
		return dwErrorCode;
	}

	// Get Signer Information.
	lRetVal = CryptMsgGetParam(lCryptMsgHandle, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)lSignerInfoPtr, &lSignerInfoSize);
	if (!lRetVal)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"CryptMsgGetParam(2) failed with error: %u", dwErrorCode);
		delete[] lSignerInfoPtr;
		return dwErrorCode;
	}

	aSignerInfo = std::shared_ptr<CMSG_SIGNER_INFO>(lSignerInfoPtr, [](PCMSG_SIGNER_INFO p) { delete[] p; });
	aCertStore = lStoreHandle;

	return ERROR_SUCCESS;
}
static DWORD getCertificateContext(std::shared_ptr <CMSG_SIGNER_INFO> aSignerInfo, HCERTSTORE aCertStore, PCCERT_CONTEXT& aCertContextPtr)
{
	CERT_INFO CertInfo = { 0 };
	CertInfo.Issuer = aSignerInfo->Issuer;
	CertInfo.SerialNumber = aSignerInfo->SerialNumber;

	auto pCertContext = CertFindCertificateInStore(aCertStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);
	if (!pCertContext)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"CertFindCertificateInStore failed with error: %u", dwErrorCode);
		return dwErrorCode;
	}

	aCertContextPtr = pCertContext;
	return ERROR_SUCCESS;
}
static DWORD getCertificateSerialNumber(PCCERT_CONTEXT aCertContext, std::wstring& aSerialNumberWstr)
{
	if (!aCertContext)
		return ERROR_INVALID_PARAMETER;

	aSerialNumberWstr = L"";

	const int lBufferSize = 3;
	wchar_t lTempBuffer[lBufferSize * 2]{ L'\0' };

	auto lDataBytesCount = aCertContext->pCertInfo->SerialNumber.cbData;
	for (DWORD n = 0; n < lDataBytesCount; n++)
	{
		auto lSerialByte = aCertContext->pCertInfo->SerialNumber.pbData[lDataBytesCount - (n + 1)];

		swprintf(lTempBuffer, lBufferSize * 2, xorstr_(L"%02x"), lSerialByte);

		aSerialNumberWstr += std::wstring(lTempBuffer, 2);
	}

	return ERROR_SUCCESS;
}
static std::wstring getCertificateSerialNumber(std::wstring aFileName)
{
	std::shared_ptr <CMSG_SIGNER_INFO> lSignerInfo;
	HCERTSTORE lCertStore;
	auto lRetVal = getSignerInfo(aFileName, lSignerInfo, lCertStore);
	if (lRetVal != ERROR_SUCCESS)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"getSignerInfo failed with error: %u", dwErrorCode);
		return L"";
	}

	PCCERT_CONTEXT lCertContext;
	lRetVal = getCertificateContext(lSignerInfo, lCertStore, lCertContext);
	if (lRetVal != ERROR_SUCCESS)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"getCertificateContext failed with error: %u", dwErrorCode);
		return L"";
	}

	std::wstring lSerialNumberWstr;
	lRetVal = getCertificateSerialNumber(lCertContext, lSerialNumberWstr);
	if (lRetVal != ERROR_SUCCESS)
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_ERR, L"getCertificateSerialNumber failed with error: %u", dwErrorCode);
		return L"";
	}

	CertFreeCertificateContext(lCertContext);
	CertCloseStore(lCertStore, CERT_CLOSE_STORE_FORCE_FLAG);

	return lSerialNumberWstr;
}

static DWORD verifyFromFile(std::wstring wstFile, bool bDisableNetworkAccess, std::wstring& wstCertProvider, std::wstring& wstCertSerial)
{
	////set up structs to verify files with cert signatures
	WINTRUST_FILE_INFO wfi{ 0 };
	memset(&wfi, 0, sizeof(wfi));
	wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
	wfi.pcwszFilePath = wstFile.c_str();
	wfi.hFile = NULL;
	wfi.pgKnownSubject = NULL;

	WINTRUST_DATA wd{ 0 };
	memset(&wd, 0, sizeof(wd));
	wd.cbStruct = sizeof(WINTRUST_DATA);
	wd.pPolicyCallbackData = NULL;
	wd.pSIPClientData = NULL;
	wd.dwUIChoice = WTD_UI_NONE;
	wd.dwUnionChoice = WTD_CHOICE_FILE;
	wd.dwStateAction = WTD_STATEACTION_VERIFY; // WTD_STATEACTION_IGNORE;
	wd.hWVTStateData = NULL;
	wd.pwszURLReference = NULL;
	wd.dwUIContext = WTD_UICONTEXT_EXECUTE;
	wd.pFile = &wfi;

	wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	wd.dwProvFlags = WTD_SAFER_FLAG | WTD_DISABLE_MD2_MD4;
	if (bDisableNetworkAccess)
	{
		wd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wd.dwProvFlags |= WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
	}

	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	auto lStatus = WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);

	if (lStatus != CERT_E_UNTRUSTEDROOT /* && lStatus != CERT_E_CHAINING && lStatus != ERROR_SUCCESS*/) // currently we only care about untrusted root
	{
		const auto dwErrorCode = GetLastError();
		APP_TRACE_LOG(LL_WARN, L"WinVerifyTrust failed with error: %u (%p) status: %u (%p)", dwErrorCode, dwErrorCode, lStatus, lStatus);
		return lStatus;
	}
	wstCertProvider = getCertificateProvider(wd.hWVTStateData);
	wstCertSerial = getCertificateSerialNumber(wstFile);

	wd.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);

	return ERROR_SUCCESS;
}
static std::wstring ExePath()
{
	wchar_t buffer[MAX_PATH]{ L'\0' };
	if (!GetModuleFileNameW(nullptr, buffer, MAX_PATH))
		return L"";

	const auto wstExeName = std::wstring(buffer);
	const auto pos = wstExeName.find_last_of(xorstr_(L"\\"));
	if (pos == std::wstring::npos)
		return L"";

	return wstExeName.substr(0, pos + 1);
}

bool __cdecl NMMV_IsValidModule()
{
	KARMA_MACRO_1;

	std::wstring wstExePath = ExePath();
	if (wstExePath.empty())
		return false;

#ifdef _M_IX86
	std::wstring MODULE_NAME = xorstr_(L"NoMercy_Module_x86.dll");
#else
	std::wstring MODULE_NAME = xorstr_(L"NoMercy_Module_x64.dll");
#endif

	wstExePath += MODULE_NAME;

	std::wstring wstCertProvider;
	std::wstring wstCertSerial;
	if (verifyFromFile(wstExePath, true, wstCertProvider, wstCertSerial) != ERROR_SUCCESS)
		return false;

	APP_TRACE_LOG(LL_TRACE, L"Certificate Provider: %s Serial: %s", wstCertProvider.c_str(), wstCertSerial.c_str());

	if (wstCertProvider != xorstr_(L"NoMercy.ac") || wstCertSerial != xorstr_(L"508a69abc0db51c98f9fbaae98fc2c04914b8d6e"))
	{
		APP_TRACE_LOG(LL_ERR, L"Invalid certificate provider or serial number!");
		return false;
	}

	return true;
}

void __cdecl NMMV_SafeExit()
{
#if (DEBUG_MODE == 0)
	KARMA_MACRO_2;
#endif

	const auto fnVirtualQuery = LI_FN(VirtualQuery).forwarded_safe_cached();
	if (fnVirtualQuery)
	{
		MEMORY_BASIC_INFORMATION mbi{};
		for (auto it = mbi.BaseAddress; fnVirtualQuery(it, &mbi, sizeof(mbi)); *reinterpret_cast<std::int64_t*>(&it) += mbi.RegionSize)
		{
			if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && mbi.Protect != PAGE_GUARD)
			{
				std::memset(mbi.BaseAddress, 0, mbi.RegionSize);
			}
		}
	}
}
