
// MShellDlgDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "MShellDlg.h"
#include "MShellDlgDlg.h"
#include "afxdialogex.h"
#include "MyPack.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CMShellDlgDlg 对话框



CMShellDlgDlg::CMShellDlgDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MSHELLDLG_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMShellDlgDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
}

BEGIN_MESSAGE_MAP(CMShellDlgDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMShellDlgDlg::OnBnClickedButton1)
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_BUTTON2, &CMShellDlgDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CMShellDlgDlg 消息处理程序

BOOL CMShellDlgDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMShellDlgDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMShellDlgDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//选择
void CMShellDlgDlg::OnBnClickedButton1()
{
	BROWSEINFO		sInfo;
	::ZeroMemory(&sInfo, sizeof(BROWSEINFO));
	sInfo.pidlRoot = 0;
	sInfo.lpszTitle = _T("请选择一个文件夹：");
	sInfo.ulFlags = BIF_DONTGOBELOWDOMAIN | BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX | BIF_USENEWUI | BIF_BROWSEINCLUDEFILES;
	sInfo.lpfn = NULL;

	// 显示文件夹选择对话框
	LPITEMIDLIST lpidlBrowse = ::SHBrowseForFolder(&sInfo);
	if (lpidlBrowse != NULL)
	{
		// 取得文件夹名
		if (::SHGetPathFromIDList(lpidlBrowse, m_szPatch))
		{
			m_edit.SetWindowText(m_szPatch);
		}
	}
	if (lpidlBrowse != NULL)
	{
		::CoTaskMemFree(lpidlBrowse);
	}
	else
	{
		return;
	}
}

//拖拽
void CMShellDlgDlg::OnDropFiles(HDROP hDropInfo)
{
	//获取文件路径
	DragQueryFile(hDropInfo, 0, m_szPatch, MAX_PATH);

	m_edit.SetWindowText(m_szPatch);

	DragFinish(hDropInfo);

	CDialogEx::OnDropFiles(hDropInfo);
}

//加壳
void CMShellDlgDlg::OnBnClickedButton2()
{
	MyPack mpack;
	if (mpack.LoadFile(m_szPatch) == FALSE)
	{
		return;
	}
	if (mpack.LoadStub("stub.dll") == FALSE)
	{
		return;
	}
	mpack.AddSection(".pack",".text");
	mpack.DealWithTLS();
	//加密IAT
	mpack.EncryIAT();
	//设置新的OEP到新区段
	mpack.SetOEP();
	// 修复壳代码的重定位
	mpack.FixDLLReloc();
	// 加密.text段
 	mpack.XOREncrySec(".text");
 	mpack.lz4Compress(".text");

	// 拷贝stub区段数据到新区段
	mpack.CopySecData(".pack", ".text");
	
	//修改重定位
	mpack.AddSection(".nreloc", ".reloc");
	mpack.FixReloc();
	mpack.CopySecData(".nreloc", ".reloc");
	
	wcscat_s(m_szPatch, L"_pack.exe");
	if(mpack.SaveFile(m_szPatch)==TRUE)
		MessageBox(L"加壳成功", L"通知",0);
	else
		MessageBox(L"加壳失败", L"通知", 0);

}
