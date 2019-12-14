// stub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>
#include <windows.h>
#include "lz4.h"
#define EDIT_PASSWORD 0x1000
#define BUTTON_OK 0x1001
// 将 .data .rdata 合并到 .text 区段，并设置属性
// 使得三个区段被存放在一起，减少依赖，方便拷贝
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
//TLS全局变量
_declspec(thread)int g_num;


//编写一个结构体，保存需要进行共享的数据
typedef struct {
	//原始OEP
	long oldOep = 0;
	//加密的rva
	long erva = 0;
	//加密的大小
	long esize = 0;
	//加密的key
	unsigned char ekey = 0;
	//原程序重定位表的RVA
	DWORD relocRVA = 0;
	//原程序的默认加载基址
	DWORD BaseImage = 0;
	//导入表 
	DWORD ImportRVA = 0;
	// 压缩前大小
	DWORD FrontCompSize = 0;
	// 压缩后的大小
	DWORD LaterCompSize = 0;
	//是否有TLS
	BOOL bTlsEable = false;
	//Tls回调函数地址
	DWORD dwCallBackAddress;


}SHAREDATA, *PSHAREDATA;

//定义函数PVirtualProtect的指针类型
typedef BOOL(WINAPI* FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FnVirtualProtect pfnVirtualProtect;


typedef VOID(WINAPI* FnExitProcess)(DWORD);
FnExitProcess pfnExitProcess;

typedef DWORD(WINAPI* FnGetWindowTextA)(HWND, CHAR*, DWORD);
FnGetWindowTextA pfnGetWindowTextA;

typedef HWND(WINAPI* FnGetDlgItem)(HWND, DWORD);
FnGetDlgItem pfnGetDlgItem;

typedef HWND(WINAPI* FnCreateWindowExA)(DWORD, const char*, const char*,
	DWORD, int,int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
FnCreateWindowExA pfnCreateWindowExA;

typedef VOID(WINAPI* FnShowWindow)(HWND, DWORD);
FnShowWindow pfnShowWindow;

typedef HMODULE(WINAPI* FnLoadLibraryA)(const char* name);
FnLoadLibraryA pfnLoadLibraryA;

typedef void*(WINAPI* FnGetProcAddress)(HMODULE, const char*);
FnGetProcAddress pfnGetProcAddress;

typedef HMODULE(WINAPI*FnGetModuleHandleA)(const char*);
FnGetModuleHandleA pfnGetModuleHandleA;

typedef DWORD(WINAPI* FnMessageBoxA)(HWND, const char*, const char*, UINT);
FnMessageBoxA pfnMessageBoxA;

typedef VOID(WINAPI* FnPostQuitMessage)(DWORD);
FnPostQuitMessage pfnPostQuitMessage;

typedef LRESULT(WINAPI* FnDefWindowProcA)(HWND, UINT, WPARAM, LPARAM);
FnDefWindowProcA pfnDefWindowProcA;

typedef HGDIOBJ(WINAPI* FnGetStockObject)(DWORD);
FnGetStockObject pfnGetStockObject;

typedef ATOM(WINAPI* FnRegisterClassA)(WNDCLASSA *);
FnRegisterClassA pfnRegisterClassA;

typedef BOOL(WINAPI* FnGetMessageA)(LPMSG, HWND, UINT, UINT);
FnGetMessageA pfnGetMessageA;

typedef BOOL(WINAPI* FnTranslateMessage)(MSG *);
FnTranslateMessage pfnTranslateMessage;

typedef LRESULT(WINAPI* FnDispatchMessageA)(MSG *);
FnDispatchMessageA pfnDispatchMessageA;

typedef LPVOID(WINAPI* FnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
FnVirtualAlloc pfnVirtualAlloc;

typedef LPVOID(WINAPI* FnVirtualFree)(LPVOID, SIZE_T, DWORD);
FnVirtualFree pfnVirtualFree;

typedef HANDLE(WINAPI* fnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
fnCreateFileA pfnCreateFileA;


struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	WORD wHigh = HIWORD(wParam);
	WORD wLow = LOWORD(wParam);

	switch (uMsg)
	{
	case WM_CLOSE:
	{
		pfnExitProcess(0);
	}
	break;
	case WM_COMMAND:
	{
		switch (wLow)
		{
		case BUTTON_OK:
			HWND hEdit = pfnGetDlgItem(hWnd, EDIT_PASSWORD);
			CHAR nBuff[100] = { 0 };
			pfnGetWindowTextA(hEdit, nBuff, 100);

			if (strcmp(nBuff, "123456") == 0)
			{
				pfnShowWindow(hWnd, SW_HIDE);
				pfnPostQuitMessage(0);
			}
			else
				pfnMessageBoxA(NULL, "密码错误", "错误", 0);
		}
		break;
	}
	break;

	}
	return pfnDefWindowProcA(hWnd, uMsg, wParam, lParam);
}
void MyDialogBox()
{

	WNDCLASSA wc = { 0 };
	wc.lpszClassName = ("password");
	wc.lpfnWndProc = &WndProc;
	wc.hbrBackground = (HBRUSH)pfnGetStockObject(WHITE_BRUSH);
	pfnRegisterClassA(&wc);

	HWND hWnd = NULL;/*窗口句柄,用于保存创建出来的窗口对象*/
	hWnd = pfnCreateWindowExA(0, "password", "密码", WS_OVERLAPPEDWINDOW, 600, 300, 250, 150, NULL, NULL, NULL, NULL);

	pfnCreateWindowExA(WS_EX_CLIENTEDGE, "Edit", "", ES_NUMBER | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE, 60, 30, 120, 30,
		hWnd, (HMENU)EDIT_PASSWORD, pfnGetModuleHandleA(0), NULL);
	pfnCreateWindowExA(0, "Button", "确认", BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE, 70, 70, 100, 30,
		hWnd, (HMENU)BUTTON_OK, pfnGetModuleHandleA(0), NULL);

	pfnShowWindow(hWnd, SW_SHOW);

	MSG msg = { 0 };
	while (pfnGetMessageA(&msg, 0, 0, 0))
	{
		pfnTranslateMessage(&msg);
		pfnDispatchMessageA(&msg);
	}

}
void beingDebugged()
{
	bool BegingDebugged = false;
	__asm
	{
		mov eax, fs:[0x30];               //获取PEB
		mov al, byte ptr ds : [eax + 0x2];//获取Peb.BegingDebugged
		mov BegingDebugged, al;
	}
	if (BegingDebugged)
	{
		pfnMessageBoxA(0, "正在被调试", 0, 0);
		pfnExitProcess(0);
	}
	else
		pfnMessageBoxA(0, "没有被调试", 0, 0);
}
void inVmWare()
{
	HANDLE hFile = (HANDLE)pfnCreateFileA("C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe", GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		pfnMessageBoxA(0, "没有VmWare", 0, 0);
	}
	else
	{
		pfnMessageBoxA(0, "检测到VmWare", 0, 0);
		pfnExitProcess(0);
	}
}
extern "C"
{
	//导出一个变量，用于接收数据
	_declspec(dllexport) SHAREDATA ShareData;

	//获得kernel32.dll的地址
	_declspec(naked) long getkernel32()
	{
		__asm {
			mov eax, dword ptr fs : [0x30]
			mov eax, dword ptr[eax + 0xC]
			mov eax, dword ptr[eax + 0xC]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax + 0x18]
			ret
		}
	}

	//设置Tls
	_declspec(dllexport) void SetTls()
	{
		beingDebugged();
		inVmWare();
		DWORD dwBase = (DWORD)pfnGetModuleHandleA(0);

		if (ShareData.bTlsEable == FALSE)return;
		DWORD nTlsCallBack = *(DWORD*)(ShareData.dwCallBackAddress - ShareData.BaseImage + dwBase);
		if (nTlsCallBack == 0) return;
		__asm
		{
			push 0;
			push DLL_PROCESS_ATTACH;
			push dwBase;
			call nTlsCallBack
		}
	}

	void uncompress()
	{
		// 1.待解压的位置
		char * pSrc = (char*)(ShareData.erva + (DWORD)pfnGetModuleHandleA(0));

		//2. 申请空间
		char* pBuff = (char*)pfnVirtualAlloc(0, ShareData.FrontCompSize,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//3. 解压缩
		LZ4_uncompress_unknownOutputSize(
			pSrc,/*压缩后的数据*/
			pBuff, /*解压出来的数据*/
			ShareData.LaterCompSize,/*压缩后的大小*/
			ShareData.FrontCompSize/*压缩前的大小*/);

		//4.修改属性
		DWORD OldProtect;
		pfnVirtualProtect(pSrc, ShareData.FrontCompSize, PAGE_EXECUTE_READWRITE, &OldProtect);

		//5.写入原始数据
		memcpy(pSrc, pBuff, ShareData.FrontCompSize);

		//6.恢复属性
		pfnVirtualProtect(pSrc, ShareData.FrontCompSize, OldProtect, &OldProtect);
		//7.释放空间
		pfnVirtualFree(pBuff, 0, MEM_RELEASE);


	}
	void DeIAT()
	{
		DWORD Module = (DWORD)pfnGetModuleHandleA(0);
		// shellcode 加密IAT
		char shellcode[] = { "\x50\x58\x60\x61\xB8\x11\x11\x11\x11\xFF\xE0" };
		//00FE12B2 | 50 | push eax |
		//00FE12B3 | 58 | pop eax | push eip; jmp xxxxxxxxx
		//00FE12B4 | 60 | pushad |
		//00FE12B5 | 61 | popad |
		//00FE12B6 | B8 11111111 | mov eax, 11111111 |
		//00FE12BB | FFE0 | jmp eax |
		// 获取原始程序导入表
		PIMAGE_IMPORT_DESCRIPTOR pImport =
			(PIMAGE_IMPORT_DESCRIPTOR)(Module + ShareData.ImportRVA);

		// 遍历导入表
		while (pImport->Name)
		{
			// 获取需要导入的dll名  RVA + Image  = VA
			char * dllName = (char*)(pImport->Name + Module);
			// 加载当前DLL
			HMODULE Mod = pfnLoadLibraryA(dllName);
			// 获取INT 
			IMAGE_THUNK_DATA * pInt = (IMAGE_THUNK_DATA *)(pImport->OriginalFirstThunk + Module);
			// 获取IAT 
			DWORD * pIat = (DWORD *)(pImport->FirstThunk + Module);
			// 遍历所有INT IAT
			while (pInt->u1.Function)
			{
				//获取函数名  
				IMAGE_IMPORT_BY_NAME * FunName = (IMAGE_IMPORT_BY_NAME*)(pInt->u1.Function + Module);
				// 获取函数真实地址
				LPVOID Fun = pfnGetProcAddress(Mod, FunName->Name);
				// 申请空间
				char * pbuff =
					(char*)pfnVirtualAlloc(0, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				// 拷贝shellcode
				memcpy(pbuff, shellcode, sizeof(shellcode));
				// 写入真正函数
				*(DWORD*)&pbuff[5] = (DWORD)Fun;

				// 修改IAT表中函数地址，需要写权限
				DWORD old;
				pfnVirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);
				// 填充到IAT
				*pIat = (DWORD)pbuff;
				pfnVirtualProtect(pIat, 4, old, &old);

				pInt++;
				pIat++;
			}

			// 下一个导入表
			pImport++;
		}


	}
	//修复Exe重定位
	void FixExeReloc()
	{
		DWORD currentBase = (DWORD)pfnGetModuleHandleA(0), OldProtect = 0;
		// 获取当前加载基址

		auto pTargetImport = PIMAGE_BASE_RELOCATION(ShareData.relocRVA + currentBase);


		// 如果 SizeOfBlock 不为空，就说明存在重定位块
		while (pTargetImport->SizeOfBlock)
		{
			// 如果重定位的数据在代码段，就需要修改访问属性
			pfnVirtualProtect((LPVOID)(pTargetImport->VirtualAddress + currentBase),
				0x1000, PAGE_READWRITE, &OldProtect);

			// 获取重定位项数组的首地址和重定位项的数量
			int count = (pTargetImport->SizeOfBlock - 8) / 2;
			TypeOffset* to = (TypeOffset*)(pTargetImport + 1);

			// 遍历每一个重定位项
			for (int i = 0; i < count; ++i)
			{
				// 如果 type 的值为 3 我们才需要关注
				if (to[i].Type == 3)
				{
					// 获取到需要重定位的地址所在的位置
					DWORD* addr = (DWORD*)(currentBase + pTargetImport->VirtualAddress + to[i].Offset);
					// 使用这个地址，计算出新的重定位后的数据
					*addr = *addr - ShareData.BaseImage + currentBase;

				}
			}

			// 还原原区段的的保护属性
			pfnVirtualProtect((LPVOID)(pTargetImport->VirtualAddress + currentBase),
				0x1000, OldProtect, &OldProtect);

			// 找到下一个重定位块
			pTargetImport = (PIMAGE_BASE_RELOCATION)
				((DWORD)pTargetImport + pTargetImport->SizeOfBlock);
		}
	}
	DWORD MyGetProcAddress(DWORD Moudle)
	{
		auto DosH = (PIMAGE_DOS_HEADER)Moudle;
		auto NTH = (PIMAGE_NT_HEADERS)(DosH->e_lfanew + Moudle);

		DWORD expRva = NTH->OptionalHeader.DataDirectory[0].VirtualAddress;
		auto expTable = (PIMAGE_EXPORT_DIRECTORY)(Moudle + expRva);

		auto ENT = (DWORD*)(expTable->AddressOfNames + Moudle);
		auto EAT = (DWORD*)(expTable->AddressOfFunctions + Moudle);
		auto EOT = (WORD*)(expTable->AddressOfNameOrdinals + Moudle);
		//遍历EAM
		for (int i = 0; i < expTable->NumberOfNames; ++i)
		{
			auto pName = (char*)(ENT[i] + Moudle);
			if (!_stricmp(pName, "GetProcAddress"))
			{
				return (EAT[EOT[i]] + Moudle);
			}
		}
		return -1;
	}
	void decryXorSex()
	{
		DWORD oldProtect;
		ShareData.erva += (DWORD)pfnGetModuleHandleA(0);

		pfnVirtualProtect((LPVOID)ShareData.erva, ShareData.esize,
			PAGE_READWRITE, &oldProtect);
		for (int i = 0; i < ShareData.esize; ++i)
		{
			((PBYTE)ShareData.erva)[i] ^= ShareData.ekey;
		}
		pfnVirtualProtect((LPVOID)ShareData.erva, ShareData.esize,
			oldProtect, &oldProtect);

	}
	_declspec (dllexport) long jmpOEP()
	{
		__asm
		{
			mov ebx, dword ptr fs : [0x30]
			mov ebx, dword ptr[ebx + 0x8]
			add ebx, ShareData.oldOep
			jmp ebx
		}
	}
	void getAPI()
	{
		pfnGetProcAddress = (FnGetProcAddress)MyGetProcAddress(getkernel32());
		HMODULE hKernel32 = (HMODULE)getkernel32();
		pfnLoadLibraryA = (FnLoadLibraryA)pfnGetProcAddress(hKernel32, "LoadLibraryA");

		HMODULE hUser32 = pfnLoadLibraryA("user32.dll");
		HMODULE hGdi32 = pfnLoadLibraryA("gdi32.dll");

		pfnMessageBoxA = (FnMessageBoxA)pfnGetProcAddress(hUser32, "MessageBoxA");
		pfnVirtualProtect = (FnVirtualProtect)pfnGetProcAddress(hKernel32, "VirtualProtect");
		pfnGetModuleHandleA = (FnGetModuleHandleA)pfnGetProcAddress(hKernel32, "GetModuleHandleA");
		pfnVirtualAlloc = (FnVirtualAlloc)pfnGetProcAddress(hKernel32, "VirtualAlloc");
		pfnVirtualFree = (FnVirtualFree)pfnGetProcAddress(hKernel32, "VirtualFree");
		pfnCreateFileA = (fnCreateFileA)pfnGetProcAddress(hKernel32, "CreateFileA");

		pfnExitProcess = (FnExitProcess)pfnGetProcAddress(hKernel32, "ExitProcess");


		pfnDefWindowProcA = (FnDefWindowProcA)pfnGetProcAddress(hUser32, "DefWindowProcA");
		pfnPostQuitMessage = (FnPostQuitMessage)pfnGetProcAddress(hUser32, "PostQuitMessage");
		pfnRegisterClassA = (FnRegisterClassA)pfnGetProcAddress(hUser32, "RegisterClassA");
		pfnCreateWindowExA = (FnCreateWindowExA)pfnGetProcAddress(hUser32, "CreateWindowExA");
		pfnShowWindow = (FnShowWindow)pfnGetProcAddress(hUser32, "ShowWindow");

		pfnGetMessageA = (FnGetMessageA)pfnGetProcAddress(hUser32, "GetMessageA");
		pfnTranslateMessage = (FnTranslateMessage)pfnGetProcAddress(hUser32, "TranslateMessage");
		pfnDispatchMessageA = (FnDispatchMessageA)pfnGetProcAddress(hUser32, "DispatchMessageA");
		pfnGetWindowTextA = (FnGetWindowTextA)pfnGetProcAddress(hUser32, "GetWindowTextA");
		pfnGetDlgItem = (FnGetDlgItem)pfnGetProcAddress(hUser32, "GetDlgItem");

		pfnGetStockObject = (FnGetStockObject)pfnGetProcAddress(hGdi32, "GetStockObject");
	}
	void Junk(DWORD funcAdd)
	{
		//花指令
		//JMP 可以分解成call 和 lea esp,[esp+4]
		__asm
		{
			call BEGIN1;
			MOV EAX, DWORD PTR FS : [0];
			PUSH EAX;
			MOV DWORD PTR FS : [0], ESP;
			POP EAX;
			MOV DWORD PTR FS : [0], EAX;
		BEGIN2:
			lea  esp, [esp + 4];
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x33)
			_asm __emit(0xDB) _asm __emit(0x90) _asm __emit(0x90)
			MOV EBP, EAX;
			call BEGIN3;
		BEGIN1:
			lea  esp, [esp + 4];
			lea edx, funcAdd;
			call BEGIN2;
		BEGIN3:
			lea  esp, [esp + 4];
			call[edx + ebx];
		}
	}
	_declspec (dllexport) _declspec (naked) void start()
	{
		g_num;

		//花指令
		__asm
		{
			//push -1 6A FF
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x6A)
			_asm __emit(0xFF) _asm __emit(0x90) _asm __emit(0x90)
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x6A)
			_asm __emit(0xFF) _asm __emit(0x90) _asm __emit(0x90)
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x6A)
			_asm __emit(0xFF) _asm __emit(0x90) _asm __emit(0x90)
			MOV EAX, DWORD PTR FS : [0];
			PUSH EAX;
			MOV DWORD PTR FS : [0], ESP;
			POP EAX;
			MOV DWORD PTR FS : [0], EAX;
			POP EAX;
			POP EAX;
			POP EAX;
			POP EAX;
			MOV EBP, EAX;
			call GETMAPI;
		GETMAPI:
			lea  esp, [esp + 4];
			PUSH - 1;
			PUSH 0;
			push getAPI;
			call Junk;
			MOV EAX, DWORD PTR FS : [0];
			PUSH EAX;
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x6A)
			_asm __emit(0x00) _asm __emit(0x90) _asm __emit(0x90)
			MOV DWORD PTR FS : [0], ESP;
			POP EAX;
			MOV DWORD PTR FS : [0], EAX;
			MOV EBP, EAX;
			call PUSHCOMP;
		MOEP:
			lea  esp, [esp + 4];
			call Junk;
		STARTCOMP:
			lea  esp, [esp + 4];
			call Junk;
			push decryXorSex;
			call STARTDECODE;
		PUSHCOMP:
			lea  esp, [esp + 4];
			push uncompress;
			call STARTCOMP;
		STARTDECODE:
			lea  esp, [esp + 4];
			call Junk;
			call DeIAT;
			call FIXRELOC;
		PASSBOX:
			push MyDialogBox;
			call Junk;
			push jmpOEP;
			call MOEP;
		FIXRELOC:
			lea  esp, [esp + 4];
			push FixExeReloc;
			call Junk;
			call SetTls;
			jmp PASSBOX;
			//pop eax 58 00
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x58)
			_asm __emit(0x00) _asm __emit(0x90) _asm __emit(0x90)
			_asm __emit(0xEB) _asm __emit(0x01) _asm __emit(0x68) _asm __emit(0x58)
			_asm __emit(0x00) _asm __emit(0x90) _asm __emit(0x90)
			POP EAX;
			POP EAX
		}
	}
}