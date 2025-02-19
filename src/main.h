#pragma once
#include <string>
#include <vector>
#include <stdint.h>

#include "KException.h"
//#include "KIf.h"

// ====================================================================
#define MY_DEBUG true

// --------------------------------------------------------------------
// グローバルオブジェクト
class KIF_Info;

class GIF_Infos
{
public:
	void push_back(const KIF_Info* pIF_Info)
		{ m_vec_IF_Infos.push_back(pIF_Info); }

	// 戻り値について
	// 1) char* は delete してはならない
	// 2) bool は Name が見つかった場合 true となる
	std::pair<const char*, bool> Get_Name_by_v6_addr(const void* p_v6_addr) const;
	// ui64_mac_addr は上位 ２byte は無視される
	// 戻り値について
	// 1) char* は delete してはならない
	// 2) bool は Name が見つかった場合 true となる
	std::pair<const char*, bool> Get_Name_by_mac_addr(const uint64_t ui64_mac_addr) const;

	void DBG_ShowSelf(FILE* fd = stdout) const;

private:
	std::vector<const KIF_Info*> m_vec_IF_Infos;
};

inline GIF_Infos g_IF_Infos;

// --------------------------------------------------------------------
// 一時的な処置

// cnt を減らす場合 true を返す
// 戻り値 : 将来利用するかも、と思って int にしているだけ
int G_AnalyzePacket(const uint8_t* pbuf, int bytes);


// --------------------------------------------------------------------
template<class T>
struct KRemovePtr
{
	using type = T;
};

template<class T>
struct KRemovePtr<T*>
{
	using type = T;
};

// --------------------------------------------------------------------
template <typename pT>
struct KInitOnce_Ptr
{
	using T = KRemovePtr<pT>::type;

	KInitOnce_Ptr() : m_ptr{ NULL } {}
	KInitOnce_Ptr(pT ptr) : m_ptr{ ptr } {}

	// ----------------------------------------------
	bool IsInited() { return (m_ptr != NULL); }

	void operator=(pT ptr) { this->InitPtr(ptr); }
	void InitPtr(pT ptr)
	{
		if (m_ptr != NULL)
			{ THROW("KInitOnce_AutoPtr : ２重に初期化されました。"); }
		m_ptr = ptr;
	}

	pT operator->() const noexcept { return m_ptr; }
	T& operator*() const noexcept { return *m_ptr; }
	pT operator()() const noexcept { return m_ptr; }
	operator pT() const noexcept { return m_ptr; }

	pT Release_Ptr()
	{
		const pT ret_val = m_ptr;
		m_ptr = NULL;
		return ret_val;
	}

protected:
	pT m_ptr;
};

// ====================================================================
class KIf_WAN;
class KIf_LAN;

inline KInitOnce_Ptr<KIf_WAN*> g_pIf_Wan;
inline KInitOnce_Ptr<KIf_LAN*> g_pIf_Lan;

