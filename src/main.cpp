#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip6.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <linux/if_link.h>

#include	"netutil.h"

#include <format>

#include "my_basic.h"
#include "KException.h"
#include "KSocket.h"
#include "KIPv6.h"

#include "main.h"


typedef struct	{
	const char	*Device1;
	const char	*Device2;
	int	DebugOut;
}PARAM;
PARAM	Param={"eth0","eth3",0};

typedef struct	{
	int	soc;
}DEVICE;
DEVICE	Device[2];

int	EndFlag=0;

// ---------------------------------------------------------------
// cnt を減らす場合 true を返す
// 戻り値 : 将来利用するかも、と思って int にしているだけ
int AnalyzePacket(const uint8_t* pbuf, int bytes);

// ---------------------------------------------------------------
int main(int argc, const char* argv[])
{
	// ---------------------------------
	if (argc != 2)
	{
		printf("argc != 2\n\n");
		return 0;
	}

	// ---------------------------------
	uint8_t buf[65535];
	int bytes_read = 0;

	try
	{
		// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		// KSocket の生成
		ifaddrs* p1st_ifaddrs = NULL;
		if (getifaddrs(&p1st_ifaddrs) < 0)
			{ THROW("getifaddrs() < 0"); }

	   // protocol = ETH_P_ALL | ETH_P_IP | ETH_P_IPV6
		// ETH_P_ALL を指定すると、送信時のパケットもキャプチャできるようになる
		KSocket w_soc{ "enp2s0", p1st_ifaddrs, ETH_P_IPV6, true };
		w_soc.Set_NickName(MGT_B("Wan_IF"));
		
		KSocket l_soc{ "enx7cc2c63c49d0", p1st_ifaddrs, ETH_P_IPV6, true };
		l_soc.Set_NickName(GRN_B("Lan_IF"));

		freeifaddrs(p1st_ifaddrs);

		g_IF_Infos.push_back(&w_soc);
		g_IF_Infos.push_back(&l_soc);

		// ---------------------------------
		// ONU 情報を追加
		KIF_Info ONU_if_info(YLW_B("ONU"));
		{
			ONU_if_info.Set_MacAddr(be64toh(0x5852'8a77'6312'0000));
			const uint64_t intf_addr = ONU_if_info.Add_v6_addr_by_cstr(argv[1]);

			uint64_t onu_v6_addr[2];
			onu_v6_addr[0] = be64toh(0xfe80'0000'0000'0000);
			onu_v6_addr[1] =intf_addr;
			ONU_if_info.Add_v6_addr_by_bin2(onu_v6_addr);

			g_IF_Infos.push_back(&ONU_if_info);
		}
		// ---------------------------------
		// 宅内ルーター情報を追加
		KIF_Info Rt_0_if_info(YLW_B("Router_0"));
		{
			Rt_0_if_info.Set_MacAddr(be64toh(0x94c6'910c'2133'0000));

			uint64_t rt_0_v6_addr[2];
			rt_0_v6_addr[0] = be64toh(0xfe80'0000'0000'0000);
			rt_0_v6_addr[1] = be64toh(0x96c6'91ff'fe0c'2133);
			Rt_0_if_info.Add_v6_addr_by_bin2(rt_0_v6_addr);

			g_IF_Infos.push_back(&Rt_0_if_info);
		}





		// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

#if MY_DEBUG
		// ---------------------------------
		// デバッグ用表示
		g_IF_Infos.DBG_ShowSelf();
#endif



#if true
		for (int cnt = 5; cnt > 0;)
		{
			bytes_read = w_soc.Read(buf, sizeof(buf));
//			if (bytes_read < (int)(sizeof(ether_header) + sizeof(ip6_hdr)))
			if (bytes_read < (int)sizeof(ether_header))
				{ THROW("bytes_read < sizeof(ether_header)"); }

			if (AnalyzePacket(buf, bytes_read) == 0) { --cnt; }
		}
#endif
	}
	catch (const KException& ex)
	{
		ex.DBG_Show();
		DBG_dump(buf, bytes_read);
	}

	return 0;
}

// ---------------------------------------------------------------
int AnalyzePacket(const uint8_t* pbuf, int bytes)
{
	if (const ether_header* peh = (const ether_header*)pbuf;
		peh->ether_type != CEV_ntohs(ETH_P_IPV6))
	{
		return -1;
#if false
		// VLAN タグ付きの場合も、現在はエラーとしている
		THROW(std::format("catch unknown ether_type -> {:#04x}"
			, ntohs(peh->ether_type)));
#endif
	}

	// 現時点では、vlan タグがないものとして想定している
	KIp_v6 v6_pckt{ pbuf, pbuf + 14 };
	v6_pckt.DBG_ShowSelf();

	return 0;
}

// ---------------------------------------------------------------
int DebugPrintf(const char *fmt,...)
{
	if(Param.DebugOut){
		va_list	args;

		va_start(args,fmt);
		vfprintf(stderr,fmt,args);
		va_end(args);
	}

	return(0);
}

// ---------------------------------------------------------------
int DebugPerror(const char *msg)
{
	if(Param.DebugOut){
		fprintf(stderr,"%s : %s\n",msg,strerror(errno));
	}

	return(0);
}

int AnalyzePacket(int deviceNo,u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct ether_header	*eh;

	ptr=data;
	lest=size;

	if(lest < (int)sizeof(ether_header)){
		DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
		return(-1);
	}
	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);
	DebugPrintf("[%d]",deviceNo);
	if(Param.DebugOut){
		PrintEtherHeader(eh,stderr);
	}

	return(0);
}

int Bridge()
{
struct pollfd	targets[2];
int	nready,i,size;
u_char	buf[2048];

	targets[0].fd=Device[0].soc;
	targets[0].events=POLLIN|POLLERR;
	targets[1].fd=Device[1].soc;
	targets[1].events=POLLIN|POLLERR;

	while(EndFlag==0){
		switch(nready=poll(targets,2,100)){
			case	-1:
				if(errno!=EINTR){
					perror("poll");
				}
				break;
			case	0:
				break;
			default:
				for(i=0;i<2;i++){
					if(targets[i].revents&(POLLIN|POLLERR)){
						if((size=read(Device[i].soc,buf,sizeof(buf)))<=0){
							perror("read");
						}
						else{
							if(AnalyzePacket(i,buf,size)!=-1){
								if((size=write(Device[(!i)].soc,buf,size))<=0){
									perror("write");
								}
							}
						}
					}
				}
				break;
		}
	}

	return(0);
}

#if false
int DisableIpForward()
{
FILE    *fp;

	if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
		DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
		return(-1);
	}
	fputs("0",fp);
	fclose(fp);

	return(0);
}
#endif

void EndSignal(int sig)
{
	EndFlag=1;
}

//////////////////////////////////////////////////////////////////
// GIF_Infos
void GIF_Infos::DBG_ShowSelf(FILE* fd) const
{
	for (const KIF_Info* p_if_info : m_vec_IF_Infos)
	{
		p_if_info->DBG_ShowSelf(fd);
	}
}

// ---------------------------------------------------------------
// GIF_Infos::Get_Name_by_v6_addr
std::pair<const char*, bool> GIF_Infos::Get_Name_by_v6_addr(const void* p_v6_addr) const
{
	for (const KIF_Info* const p_if_info : m_vec_IF_Infos)
	{
		if (p_if_info->Contains_v6_addr((const uint64_t*)p_v6_addr))
			{ return { p_if_info->Get_Name().c_str(), true }; }
	}

	return { KIF_Info::CStr_frm_v6_addr((const uint8_t*)p_v6_addr), false };
}

// ---------------------------------------------------------------
// GIF_Infos::Get_Name_by_mac_addr
std::pair<const char*, bool> GIF_Infos::Get_Name_by_mac_addr(uint64_t ui64_mac_addr) const
{
	ui64_mac_addr &= 0xffff'ffff'ffff;

	for (const KIF_Info* const p_if_info : m_vec_IF_Infos)
	{
		if (p_if_info->mac_addr() == ui64_mac_addr)
			{ return { p_if_info->Get_Name().c_str(), true }; }
	}

	return { KIF_Info::CStr_frm_mac_addr(ui64_mac_addr), false };
}
