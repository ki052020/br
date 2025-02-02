#pragma once
#include <string>
#include <vector>
#include <stdint.h>

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

