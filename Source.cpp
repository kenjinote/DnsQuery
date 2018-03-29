#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "dnsapi")
#pragma comment(lib, "ws2_32")

#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <regex>

TCHAR szClassName[] = TEXT("Window");

void ReverseIP(LPWSTR pIP)
{
	WCHAR seps[] = L".";
	WCHAR *token;
	WCHAR pIPSec[4][4];
	int i = 0;
	LPWSTR context;
	token = wcstok_s(pIP, seps, &context);
	while (token != NULL)
	{
		wsprintfW(pIPSec[i], L"%s", token);
		token = wcstok_s(NULL, seps, &context);
		i++;
	}
	wsprintfW(pIP, L"%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0], L"IN-ADDR.ARPA");
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEdit1;
	static HWND hButton;
	static HWND hEdit2;
	switch (msg)
	{
	case WM_CREATE:
		hEdit1 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), TEXT("hack.jp"), WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton = CreateWindow(TEXT("BUTTON"), TEXT("取得"), WS_VISIBLE | WS_CHILD, 0, 0, 0, 0, hWnd, (HMENU)IDOK, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hEdit2 = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("EDIT"), 0, WS_VISIBLE | WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOHSCROLL | ES_AUTOVSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		break;
	case WM_SIZE:
		MoveWindow(hEdit1, 10, 10, 256, 32, TRUE);
		MoveWindow(hButton, 10, 50, 256, 32, TRUE);
		MoveWindow(hEdit2, 10, 90, LOWORD(lParam) - 20, HIWORD(lParam) - 100, TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			SetWindowText(hEdit2, 0);
			WCHAR szInput[1024];
			GetWindowTextW(hEdit1, szInput, _countof(szInput));
			int nType;
			if (std::regex_match(szInput, std::wregex(L"^\\d+\\.\\d+\\.\\d+\\.\\d+$")))
			{
				nType = DNS_TYPE_PTR;
				ReverseIP(szInput);
			}
			else
			{
				nType = DNS_TYPE_A;
			}
			DNS_FREE_TYPE freetype = DnsFreeRecordListDeep;
			PDNS_RECORDW pDnsRecord = NULL;
			DNS_STATUS status = DnsQuery_W(szInput, nType, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL);
			if (status == 0)
			{
				PDNS_RECORD pDnsRecordsToDelete = pDnsRecord;
				while (pDnsRecord != nullptr)
				{
					switch (pDnsRecord->wType)
					{
						case DNS_TYPE_A:
						{
							SOCKADDR_IN addr;
							memset(&addr, 0, sizeof(addr));
							addr.sin_family = AF_INET;
							addr.sin_addr = *((in_addr*)&(pDnsRecord->Data.A.IpAddress));
							CHAR buf[128];
							DWORD bufSize = sizeof(buf);
							if (WSAAddressToStringA((sockaddr*)&addr, sizeof addr, NULL, buf, &bufSize) == 0)
							{
								SendMessageA(hEdit2, EM_REPLACESEL, 0, (LPARAM)buf);
								SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("\r\n"));
							}
							break;
						}
						case DNS_TYPE_AAAA:
						{
							SOCKADDR_IN6 addr;
							memset(&addr, 0, sizeof(addr));
							addr.sin6_family = AF_INET6;
							addr.sin6_addr = *((in_addr6*)&(pDnsRecord->Data.AAAA.Ip6Address));
							CHAR buf[128];
							DWORD bufSize = sizeof(buf);
							if (WSAAddressToStringA((sockaddr*)&addr, sizeof addr, NULL, buf, &bufSize) == 0)
							{
								SendMessageA(hEdit2, EM_REPLACESEL, 0, (LPARAM)buf);
								SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("\r\n"));
							}
							break;
						}
						case DNS_TYPE_CNAME:
						{
							SendMessageW(hEdit2, EM_REPLACESEL, 0, (LPARAM)pDnsRecord->Data.CNAME.pNameHost);
							SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("\r\n"));
							break;
						}
						case DNS_TYPE_MX:
						{
							SendMessageW(hEdit2, EM_REPLACESEL, 0, (LPARAM)pDnsRecord->Data.MX.pNameExchange);
							SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("\r\n"));
							break;
						}
						case DNS_TYPE_TEXT:
						{
							for (u_int i = 0; i < pDnsRecord->Data.TXT.dwStringCount; i++)
							{
								SendMessageW(hEdit2, EM_REPLACESEL, 0, (LPARAM)pDnsRecord->Data.TXT.pStringArray[i]);
								SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("\r\n"));
							}
							break;
						}
						case DNS_TYPE_PTR:
						{
							SendMessageW(hEdit2, EM_REPLACESEL, 0, (LPARAM)pDnsRecord->Data.PTR.pNameHost);
							SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("\r\n"));
							break;
						}
						default:
						{
							SendMessage(hEdit2, EM_REPLACESEL, 0, (LPARAM)TEXT("Unknown\r\n"));
							break;
						}
					}
					pDnsRecord = pDnsRecord->pNext;
				}
				DnsRecordListFree(pDnsRecordsToDelete, freetype);
			}
			else
			{
				SetWindowText(hEdit2, TEXT("取得できませんでした"));
			}						
		}
		break;
	case WM_CLOSE:
		DestroyWindow(hWnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefDlgProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 0), &wsaData);

	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		DLGWINDOWEXTRA,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("DNS を使ってドメイン名⇔ IP アドレスの対応を取得"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0))
	{
		if (!IsDialogMessage(hWnd, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	WSACleanup();
	return (int)msg.wParam;
}
