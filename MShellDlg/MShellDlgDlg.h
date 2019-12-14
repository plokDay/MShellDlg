
// MShellDlgDlg.h: 头文件
//

#pragma once


// CMShellDlgDlg 对话框
class CMShellDlgDlg : public CDialogEx
{
// 构造
public:
	CMShellDlgDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MSHELLDLG_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CEdit m_edit;
	TCHAR  m_szPatch[MAX_PATH] = { 0 };
	afx_msg void OnBnClickedButton1();
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnBnClickedButton2();
};
