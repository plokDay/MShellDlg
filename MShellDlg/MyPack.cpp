#include "stdafx.h"
#include "MyPack.h"
#include "lz4.h"

MyPack::MyPack()
{
}


MyPack::~MyPack()
{
}
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
PIMAGE_DOS_HEADER MyPack::GetDosHeader(DWORD buff)
{
	return PIMAGE_DOS_HEADER(buff);
}

PIMAGE_NT_HEADERS MyPack::GetNTHeaders(DWORD buff)
{
	return PIMAGE_NT_HEADERS(GetDosHeader(buff)->e_lfanew + buff);
}

PIMAGE_FILE_HEADER MyPack::GetFileHeader(DWORD buff)
{
	return &GetNTHeaders(buff)->FileHeader;
}

PIMAGE_OPTIONAL_HEADER MyPack::GetOptHeader(DWORD buff)
{
	return &GetNTHeaders(buff)->OptionalHeader;
}
//获取区段头
PIMAGE_SECTION_HEADER MyPack::GetSecHeader(DWORD buff)
{
	return IMAGE_FIRST_SECTION(GetNTHeaders(buff));
}
PIMAGE_SECTION_HEADER MyPack::GetSection(DWORD buff, LPCSTR SectionName)
{
	//1. 获取区段表的第一项
	auto SectionTable = IMAGE_FIRST_SECTION(GetNTHeaders(buff));
	//2. 遍历所有区段
	for (int i = 0; i < GetFileHeader(buff)->NumberOfSections; ++i)
	{
		if (!memcmp((PVOID)SectionName, SectionTable[i].Name, 8))
		{
			return &SectionTable[i];
		}
	}
	return nullptr;

}

DWORD MyPack::Alignment(DWORD n, DWORD align)
{
	return n % align == 0 ? n : (n / align + 1)*align;
}

//获取重定位表的rva
DWORD MyPack::GetRelocRVA()
{
	return GetOptHeader(fileBuff)->DataDirectory[5].VirtualAddress;
}


BOOL MyPack::IsPE()
{
	if (GetDosHeader(fileBuff)->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	if (GetNTHeaders(fileBuff)->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	return TRUE;
}
//加载PE文件到缓冲区
BOOL MyPack::LoadFile(LPCWSTR FileName)
{
	//1.如果文件存在就打开文件
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, NULL,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"文件打开失败", L"错误", 0);
		return FALSE;
	}
	//2.求文件大小,并使用这个大小申请缓冲区
	fileSize = GetFileSize(hFile, NULL);
	fileBuff = (DWORD)calloc(fileSize, sizeof(BYTE));
	//3.读入内存
	DWORD Read = 0;
	ReadFile(hFile, (LPVOID)fileBuff, fileSize, &Read, NULL);
	//4.判断是否是PE文件
	if (IsPE() == FALSE)
	{
		MessageBox(0, L"不是PE文件", L"错误", 0);
		CloseHandle(hFile);
		return FALSE;
	}
	//5.关闭句柄
	CloseHandle(hFile);
	return TRUE;
}
//加载stub到内存中
BOOL MyPack::LoadStub(LPCSTR dllName)
{
	//以不执行DLLMain的方式加载dll模块
	DllBase = (DWORD)LoadLibraryExA(dllName,
		NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (DllBase == NULL)
	{
		MessageBox(0, L"dll加载错误", L"错误", 0);
		return FALSE;
	}
	//从dll中获取start函数，并计算它的VA
	DWORD StartAdd = (DWORD)GetProcAddress((HMODULE)DllBase, "start");
	if (StartAdd == NULL)
	{
		MessageBox(0, L"获取start函数地址错误", L"错误", 0);
		return FALSE;
	}
	startOffset = StartAdd - DllBase - GetSection(DllBase, ".text")->VirtualAddress;
	//获取共享信息
	ShareData = (PSHAREDATA)GetProcAddress((HMODULE)DllBase, "ShareData");
	
	SetTLS = (DWORD)GetProcAddress((HMODULE)DllBase, "SetTls");

	ShareData->relocRVA = GetRelocRVA();//保存原程序重定位表的RVA
	ShareData->BaseImage = GetOptHeader(fileBuff)->ImageBase;//保存原程序加载基址
	ShareData->ImportRVA = (DWORD)GetOptHeader(fileBuff)->DataDirectory[1].VirtualAddress;
}

int MyPack::RvaToFoa(DWORD Rva)
{
	PIMAGE_NT_HEADERS pNt = GetNTHeaders(fileBuff);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (Rva >= pSection->VirtualAddress&&
			Rva <= pSection->VirtualAddress + pSection->Misc.VirtualSize)
		{
			// 如果文件地址为0,将无法在文件中找到对应的内容
			if (pSection->PointerToRawData == 0)
			{
				return -1;
			}
			return Rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection = pSection + 1;
	}
	return -1;
}

VOID MyPack::EncryIAT()
{
	GetOptHeader(fileBuff)->DataDirectory[1].VirtualAddress = 0;
	GetOptHeader(fileBuff)->DataDirectory[1].Size = 0;
						  
	GetOptHeader(fileBuff)->DataDirectory[12].VirtualAddress = 0;
	GetOptHeader(fileBuff)->DataDirectory[12].Size = 0;
}

VOID MyPack::SetOEP()
{
	ShareData->oldOep = GetOptHeader(fileBuff)->AddressOfEntryPoint;//保存旧的OEP
	DWORD a = GetSection(fileBuff, ".pack")->VirtualAddress;
	GetOptHeader(fileBuff)->AddressOfEntryPoint = startOffset +
		GetSection(fileBuff, ".pack")->VirtualAddress;
}
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};
//修复壳代码的重定位
VOID MyPack::FixDLLReloc()
{
	DWORD Size = 0, oldProtect = 0;
	//获取重定位表
	auto RelocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, &Size);
	//如果SizeofTable不为空，说明存在重定位块
	while (RelocTable->SizeOfBlock)
	{
		//修改访问属性
		VirtualProtect((LPVOID)(DllBase + RelocTable->VirtualAddress),
			0x1000, PAGE_READWRITE, &oldProtect);
		//获取重定位的数量
		int relCount = (RelocTable->SizeOfBlock - 8) / 2;
		//获得重定位块
		TypeOffset* pBlock = (TypeOffset *)(RelocTable + 1);
		for (int i = 0; i < relCount; ++i)
		{
			if (pBlock[i].Type == 3)
			{
				//需要重定位的位置
				DWORD* addr = (DWORD*)(DllBase + RelocTable->VirtualAddress
					+ pBlock[i].Offset);
				//段内偏移
				DWORD itemOffset = *addr - DllBase - GetSection(DllBase, ".text")->VirtualAddress;
				//新重定位后的数据
				*addr = itemOffset + GetOptHeader(fileBuff)->ImageBase +
					GetSection(fileBuff, ".pack")->VirtualAddress;
			}
		}
		//修改访问属性
		VirtualProtect((LPVOID)(DllBase + RelocTable->VirtualAddress),
			0x1000, oldProtect, &oldProtect);
		//找到下一个重定位段
		RelocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RelocTable + RelocTable->SizeOfBlock);

	}
	

}

VOID MyPack::CopySecData(LPCSTR desSec, LPCSTR srcSec)
{
	auto srcData = (PBYTE)(GetSection(DllBase, srcSec)->VirtualAddress + DllBase);
	auto desData = (PBYTE)(GetSection(fileBuff, desSec)->PointerToRawData + fileBuff);
	memcpy(desData, srcData, GetSection(DllBase, srcSec)->SizeOfRawData);
}

VOID MyPack::XOREncrySec(LPCSTR secName)
{
	//1. 获得要加密区段的信息
	auto enSec = GetSection(fileBuff, ".text");
	//2. 获取加密字段在内存中的位置
	PBYTE enData = (PBYTE)(enSec->PointerToRawData + fileBuff);
	//3. 填写解密时需要提供的信息
	srand((unsigned int)time(0));
	ShareData->ekey = rand() % 0xff;
	ShareData->erva = enSec->VirtualAddress;
	ShareData->esize = enSec->SizeOfRawData;
	//4. 开始循环加密
	for (int i=0;i<ShareData->esize;++i)
	{
		enData[i] ^= ShareData->ekey;
	}
	
}
//从stub复制新区段,并设置新的OEP
VOID MyPack::AddSection(LPCSTR desSec,LPCSTR srcSec)
{
	//1. 获取到区段表最后一个元素的地址
	auto LastSection = IMAGE_FIRST_SECTION(GetNTHeaders(fileBuff)) +
		(GetFileHeader(fileBuff)->NumberOfSections - 1);
	//2. 找到新添加区段的位置
	auto NewSec = LastSection + 1;
	//3. 区段数量+1
	GetFileHeader(fileBuff)->NumberOfSections += 1;
	//4. 从dll中找到源区段
	auto srcSection = GetSection(DllBase, srcSec);
	//5. 从源区段拷贝区段头信息
	memcpy(NewSec, srcSection, sizeof(IMAGE_SECTION_HEADER));
	//6. 设置新区段头中的数据
	memcpy(NewSec->Name, desSec, 7);
	//7. 设置新区段的RVA=上一个区段的RVA+对齐的内存大小
	NewSec->VirtualAddress = LastSection->VirtualAddress +
		Alignment(LastSection->Misc.VirtualSize, GetOptHeader(fileBuff)->SectionAlignment);
	//8. 设置新区段的FOA=上一个区段的FOA+对齐的文件大小
	NewSec->PointerToRawData = LastSection->PointerToRawData +
		Alignment(LastSection->SizeOfRawData, GetOptHeader(fileBuff)->FileAlignment);
	//10. 修改SizeOfImage
	GetOptHeader(fileBuff)->SizeOfImage =
		NewSec->VirtualAddress + NewSec->Misc.VirtualSize;
	//如果要添加的新区段是重定位，就改变原程序的重定位表
	if (strcmp(srcSec, ".reloc") == 0)
	{
		GetOptHeader(fileBuff)->DataDirectory[5].VirtualAddress = NewSec->VirtualAddress;
		GetOptHeader(fileBuff)->DataDirectory[5].Size = NewSec->Misc.VirtualSize;
	}
	//9. 重新计算文件大小，申请新的空间
	fileSize = NewSec->SizeOfRawData + NewSec->PointerToRawData;
	fileBuff = (DWORD)realloc((VOID*)fileBuff, fileSize);
	
	

}
VOID MyPack::lz4Compress(const char* SectionName)
{
	PIMAGE_SECTION_HEADER ptext = GetSection(fileBuff, SectionName);
	PIMAGE_SECTION_HEADER ptextNext = ptext + 1;

	//1. 获取字段在内存中的位置
	auto textData = (char*)(ptext->PointerToRawData + fileBuff);

	// 保存压缩前信息
	// 压缩前大小Size
	ShareData->FrontCompSize = ptext->SizeOfRawData;


	// ---------------------------------开始压缩
	// 1 获取预估的压缩后的字节数:
	int compress_size = LZ4_compressBound(ShareData->FrontCompSize);
	// 2. 申请内存空间, 用于保存压缩后的数据
	char* pBuff = new char[compress_size];
	// 3. 开始压缩文件数据(函数返回压缩后的大小)

	ShareData->LaterCompSize = LZ4_compress(
		(const char*)textData,/*压缩前的数据*/
		pBuff, /*压缩后的数据*/
		ptext->SizeOfRawData/*文件原始大小*/);

	memcpy(textData, pBuff, ShareData->LaterCompSize);

	//修改区段头表的数据
	ptext->SizeOfRawData = Alignment(ShareData->LaterCompSize, 0x200);
	//3. 下一区段到文件末尾
	// 没有后一个区段，就不需要提升
	while (ptextNext->VirtualAddress)
	{
		// 当前区段大小
		long DesSize = ptext->SizeOfRawData;
		// 移动到这个区段后面
		char * pDest = (char*)(ptext->PointerToRawData + fileBuff + DesSize);

		// 下个区段大小
		long SrcSize = ptextNext->SizeOfRawData;
		// 下一个区段位置
		char * pSrc = (char*)(ptextNext->PointerToRawData + fileBuff);

		// 拷贝区段
		memcpy(pDest, pSrc, SrcSize);

		// 修改下个区段位置 不加FileBase，应为不是在内存中
		ptextNext->PointerToRawData = ptext->PointerToRawData + DesSize;

		// 继续提升下个区段
		ptext += 1;
		ptextNext += 1;

	}
	// 7.重新修改文件实际大小
// 实际大小 = 最后一个区段位置 + 最后区段大小
	fileSize = ptext->PointerToRawData + ptext->SizeOfRawData;

	// 8.重新修改文件大小
	fileBuff = (DWORD)realloc((VOID*)fileBuff, fileSize);

	// 9.释放空间
	delete[]pBuff;
}
//保存文件 
BOOL MyPack::SaveFile(LPCWSTR FileName)
{
	HANDLE hFile = CreateFile(FileName, GENERIC_WRITE, NULL,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"文件打开失败", L"错误", 0);
		return FALSE;

	}
	DWORD Write = 0;
	WriteFile(hFile, (LPVOID)fileBuff, fileSize, &Write, NULL);
	CloseHandle(hFile);
	return TRUE;
}
// 修正重定位表
VOID MyPack::FixReloc()
{
	DWORD Size = 0, OldProtect = 0;

	// 获取到程序的重定位表
	auto RealocTable = (PIMAGE_BASE_RELOCATION)
		ImageDirectoryEntryToData((PVOID)DllBase, TRUE, 5, &Size);

	// 如果 SizeOfBlock 不为空，就说明存在重定位块
	while (RealocTable->SizeOfBlock)
	{
		// 重定位中VirtualAddress 字段进行修改，需要把重定位表变成可写
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x4, PAGE_READWRITE, &OldProtect);

		// 修正VirtualAddress，从壳中的text到 目标程序pack段
		// 修复公式 ：VirtualAddress - 壳.text.VirtualAddress  + 目标程序.pack.VirtualAddress
		RealocTable->VirtualAddress -= GetSection(DllBase, ".text")->VirtualAddress;
		RealocTable->VirtualAddress += GetSection(fileBuff, ".pack")->VirtualAddress;
		// 还原原区段的的保护属性
		VirtualProtect((LPVOID)(&RealocTable->VirtualAddress),
			0x1000, OldProtect, &OldProtect);

		// 找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}

	return;
}

VOID MyPack::DealWithTLS() {
	//获取扩展头
	IMAGE_OPTIONAL_HEADER *pOptionHeader = GetOptHeader(fileBuff);
	DWORD dwImageBase = pOptionHeader->ImageBase;

	//判断TLS是否存在
	if (pOptionHeader->DataDirectory[9].VirtualAddress == 0) {
		ShareData->bTlsEable = FALSE;
	}
 	else 
	{
		//关闭程序的重定位
		GetOptHeader(fileBuff)->DllCharacteristics = 0x8100;
		ShareData->bTlsEable = TRUE;
		PIMAGE_TLS_DIRECTORY32 g_lpTlsDir =
			(PIMAGE_TLS_DIRECTORY32)(RvaToFoa(pOptionHeader->DataDirectory[9].VirtualAddress) + fileBuff);
		ShareData->dwCallBackAddress = g_lpTlsDir->AddressOfCallBacks;
		DWORD dwOld = 0;
		DWORD a = g_lpTlsDir->AddressOfCallBacks - ShareData->BaseImage;//VA->RVA
		a = RvaToFoa(a);
		a += fileBuff;
		VirtualProtect((PVOID)a, 4, PAGE_READWRITE, &dwOld);
		a = SetTLS - DllBase -
			GetSection(DllBase,".text")->VirtualAddress + GetSection(fileBuff,".pack")->VirtualAddress
			+ ShareData->BaseImage;//0x426830; 
		VirtualProtect((PVOID)a, 4, dwOld, &dwOld);

	}
}
