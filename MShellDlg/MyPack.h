#pragma once
#include <windows.h>

typedef struct {
	//原始OEP
	long oldOep = 0;
	//加密的rva, 压缩的RVA
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

class MyPack
{
public:
	MyPack();
	~MyPack();
private:
	DWORD fileBuff = 0;//文件申请的空间
	DWORD fileSize = 0;//文件大小
	DWORD startOffset = 0;//保存start函数的段内偏移，用以计算新OEP
	PSHAREDATA ShareData = nullptr; // 保存共享数据块，主要用于提供信息给壳代码
	DWORD SetTLS = 0; // 保存共享数据块，主要用于提供信息给壳代码
	DWORD DllBase = 0;//dll的加载基址

private:
	//工具函数，用于读取PE文件信息
	PIMAGE_DOS_HEADER GetDosHeader(DWORD buff);
	PIMAGE_NT_HEADERS GetNTHeaders(DWORD buff);
	PIMAGE_FILE_HEADER GetFileHeader(DWORD buff);
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD buff);
	BOOL IsPE();
	PIMAGE_SECTION_HEADER GetSecHeader(DWORD buff);
	PIMAGE_SECTION_HEADER GetSection(DWORD buff, LPCSTR SectionName);
	DWORD Alignment(DWORD n, DWORD align);//用于按照指定字节对齐
	DWORD GetRelocRVA();

public:
	//1.读取PE文件到内存
	BOOL LoadFile(LPCWSTR FileName);

	//2.加载stub.dll
	BOOL LoadStub(LPCSTR dllName);

	//IAT加密
	int RvaToFoa(DWORD Rva);
	VOID EncryIAT();
	VOID SetOEP();//保存旧的OEP，设置新的OEP
	VOID FixDLLReloc();//修复壳代码的重定位
	VOID CopySecData(LPCSTR desSec, LPCSTR srcSec);//复制.text的区段数据到.pack
	VOID XOREncrySec(LPCSTR secName);//加密某个区段

	//3.从stub的.text复制到新区段.pack，并设置OEP到.pack
	VOID AddSection(LPCSTR desSec, LPCSTR srcSec);
	//压缩
	VOID lz4Compress(const char* SectionName);
	//4.保存新文件
	BOOL SaveFile(LPCWSTR FileName);
	VOID FixReloc();//修复.nreloc的重定位
	VOID DealWithTLS();//处理TLS
};

