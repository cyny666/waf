#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_ICMP_TYPES 10

unsigned int controlled_protocol = 0;	//协议名
unsigned short controlled_srcport = 0;	//源端口号
unsigned short controlled_dstport = 0;	//目的端口号
unsigned int controlled_saddr = 0;	//源IP地址
unsigned int controlled_daddr = 0; 	//目的IP地址

//时间控制信息
int controlled_time_flag=0; //0表示时间判断功能关闭
unsigned int  controlled_time_begin=0;
unsigned int controlled_time_end=0;
int icmp_type[9]={0,0,0,0,0,0,0,0,0};

//网络接口
int controlled_interface=0;
// 回显应答报文（Echo Reply）：宏定义 ICMP_ECHOREPLY，值为 0。
// 回显请求报文（Echo Request）：宏定义 ICMP_ECHO，值为 8。
// 目标不可达报文（Destination Unreachable）：宏定义 ICMP_DEST_UNREACH，值为 3。
// 超时报文（Time Exceeded）：宏定义 ICMP_TIME_EXCEEDED，值为 11。
// 参数问题报文（Parameter Problem）：宏定义 ICMP_PARAMETERPROB，值为 12。
// 源抑制报文（Source Quench）：宏定义 ICMP_SOURCE_QUENCH，值为 4。
// 重定向报文（Redirect）：宏定义 ICMP_REDIRECT，值为 5。
// 时间戳请求报文（Timestamp Request）：宏定义 ICMP_TIMESTAMP，值为 13。
// 时间戳应答报文（Timestamp Reply）：宏定义 ICMP_TIMESTAMPREPLY，值为 14。


//表示1条规则的结构体，大小为18*4=72字节
struct Rule
{
unsigned int m_controlled_protocol;	//协议名
unsigned short m_controlled_srcport;	//源端口号
unsigned short m_controlled_dstport;	//目的端口号
unsigned int m_controlled_saddr;	//源IP地址
unsigned int m_controlled_daddr; 	//目的IP地址

//时间控制信息
int m_controlled_time_flag; //0表示时间判断功能关闭
unsigned int  m_controlled_time_begin;
unsigned int m_controlled_time_end;
int m_icmp_type[9];
int m_controlled_interface;

//int m_index;    //规则序号
};

//规则默认初始化
void initial_rules(struct Rule *rule){
rule->m_controlled_protocol = 0;	//协议名
rule->m_controlled_srcport = 0;	//源端口号
rule->m_controlled_dstport = 0;	//目的端口号
rule->m_controlled_saddr = 0;	//源IP地址
rule->m_controlled_daddr = 0; 	//目的IP地址

//时间控制信息
rule->m_controlled_time_flag=0; //0表示时间判断功能关闭
rule->m_controlled_time_begin=0;
rule->m_controlled_time_end=0;
for(int i=0;i<9;++i)
    rule->m_icmp_type[i]=0;
//网络接口
rule->m_controlled_interface=0;
}


void display_usage(char *commandname)	//输出显示命令用法
{
	printf("Usage 1: %s \n", commandname);
	printf("Usage 2: %s -x saddr -y daddr -m srcport -n dstport -t time_control \n", commandname);
}

//命令行参数解析的函数
int getpara(int argc, char *argv[],struct Rule* rule){
	int optret;	//
	unsigned short tmpport;	//存储临时端口号

 	char *icmp_types[MAX_ICMP_TYPES];
    int num_icmp_types = 0;

	optret = getopt(argc,argv,"pxymnhbeti");
	while( optret != -1 ) {		
//			printf(" first in getpara: %s\n",argv[optind]);
        	switch( optret ) {
        	case 'p':	//-p protocol 指明要控制的协议（或网络应用）类型，具体为 tcp、udp、icmp三种之一；
        		if (strncmp(argv[optind], "icmp",4) == 0 )
					rule->m_controlled_protocol = 1;
				else if ( strncmp(argv[optind], "tcp",3) == 0  )
					rule->m_controlled_protocol = 6;
				else if ( strncmp(argv[optind], "udp",3) == 0 )
					rule->m_controlled_protocol = 17;
				else {
					printf("Unkonwn protocol! please check and try again! \n");
					exit(1);
				}
        		break;
         case 'x':   //get source ipaddr， –x source_ip 指明要控制报文的源IP地址；
				if ( inet_aton(argv[optind], (struct in_addr* )&rule->m_controlled_saddr) == 0){
					printf("Invalid source ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'y':   //get destination ipaddr，–y dst_ip 指明要控制报文的目标IP地址；
				if ( inet_aton(argv[optind], (struct in_addr* )&rule->m_controlled_daddr) == 0){
					printf("Invalid destination ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'm':   //get destination ipaddr， –m source_port 指明要控制报文的源端口地址；
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				rule->m_controlled_srcport = htons(tmpport);
         	break;
        case 'n':   //get destination ipaddr，–n dst_port 指明要控制报文的目标端口；
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				rule->m_controlled_dstport = htons(tmpport);
         	break;

        case 'b':
				const char *time_str_begin=argv[optind];
				struct tm time_info_begin;
				// 解析时间字符串
				if (strptime(time_str_begin, "%H:%M", &time_info_begin) == NULL) {
					printf("开始时间解析失败\n");
					exit(1);
				}
                rule->m_controlled_time_flag=1;
                rule->m_controlled_time_begin=time_info_begin.tm_hour*60+time_info_begin.tm_min;
                break;
        case 'e':
				const char *time_str_end=argv[optind];
				struct tm time_info_end;
				// 解析时间字符串
				if (strptime(time_str_end, "%H:%M", &time_info_end) == NULL) {
					printf("结束时间解析失败\n");
					exit(1);
				}
                rule->m_controlled_time_flag=1;
                rule->m_controlled_time_end=time_info_end.tm_hour*60+time_info_end.tm_min;
                break;
		case 't':
				
				int tmp_icmp_type = atoi(argv[optind]);
                if (tmp_icmp_type == 0){
					printf("Invalid icmp type! please check and try again! \n ");
					exit(1);
				}
				rule->m_icmp_type[tmp_icmp_type-1]=1;
                break;
        case 'i':
                int tmp_interface=atoi(argv[optind]);
                if(tmp_interface==0){
                    printf("Invalid network interface! please check and try again! \n ");
					exit(1);
                }
                rule->m_controlled_interface=tmp_interface;
                break;


         case 'h':   /* fall-through is intentional ，故意失败*/ 
         case '?':	//当解析到未知选项或无效选项时执行的操作。
		 				//在这种情况下，通常会显示用法信息，并通过调用 display_usage(argv[0]) 函数来打印程序的使用说明。
						//然后，使用 exit(1) 终止程序的执行，并返回退出状态码 1，
         	display_usage(argv[0]);
         	exit(1);
                
         default:
				printf("Invalid parameters! \n ");
         	display_usage(argv[0]);
         	exit(1);
        	}
		optret = getopt(argc,argv,"pxymnhbeti");
	}


}

int main(int argc, char *argv[]){
	char controlinfo[128];
	int controlinfo_len = 0;
	int fd;
	struct stat buf;	//stat 结构体是用来存储文件或文件系统对象的状态信息的，例如文件的大小、访问权限、修改时间等。
								//通过使用 struct stat buf，可以在程序中获取和操作文件的各种属性和元数据。
	
	if (argc == 1) 
		controlinfo_len = 0; //cancel the filter
	else if (argc > 1){
        struct Rule tmp_rule;
        initial_rules(&tmp_rule);


		getpara(argc, argv,&tmp_rule);
        *(struct Rule *)controlinfo = tmp_rule;
		// *(int *)controlinfo = controlled_protocol;
		// *(int *)(controlinfo + 4) = controlled_saddr;
		// *(int *)(controlinfo + 8) = controlled_daddr;
		// *(int *)(controlinfo + 12) = controlled_srcport;
		// *(int *)(controlinfo + 16) = controlled_dstport;
        // *(int *)(controlinfo + 20) = controlled_time_flag;
        // *(int *)(controlinfo + 24) = controlled_time_begin;
        // *(int *)(controlinfo + 28) = controlled_time_end;
        // for(int i=0;i<9;++i){
		// 	*(int *)(controlinfo + 32 + 4*i) = icmp_type[i];
		// }
        // *(int *)(controlinfo + 68) = controlled_interface;
		controlinfo_len =sizeof(tmp_rule);
	}
	
//	printf("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);

	if (stat("/dev/controlinfo",&buf) != 0){	//这段代码是在检查文件/dev/controlinfo的状态。
                                                                    //stat 函数用于获取文件的状态信息，并将结果存储在提供的结构体变量 buf 中。
		/*这段代码是在尝试通过系统命令mknod创建一个名为/dev/controlinfo的字符设备文件。
		mknod命令用于创建设备文件，其中c表示创建字符设备文件，124表示设备文件的主设备号，0表示设备文件的次设备号。*/
		if (system("mknod /dev/controlinfo c 124 0") == -1){	
			printf("Cann't create the devive file ! \n");
			printf("Please check and try again! \n");
			exit(1);
		}
	}

	/*将字符串controlinfo的命令信息写入到字符设备文件"/dev/controlinfo"中*/
	fd =open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
	if (fd > 0)
	{
		write(fd,controlinfo,controlinfo_len);
	}
	else {
		perror("can't open /dev/controlinfo \n");
	 	exit(1);
	}
	close(fd);
}

