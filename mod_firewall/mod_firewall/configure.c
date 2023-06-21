#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include	<stdlib.h>

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0; 
// 展示程序的使用说明
void display_usage(char *commandname)
{
	printf("Usage 1: %s \n", commandname);
	printf("Usage 2: %s -x saddr -y daddr -m srcport -n dstport \n", commandname);
}
// 解析命令行参数并获取相应的参数值
int getpara(int argc, char *argv[]){
	int optret;
	unsigned short tmpport;
    // argc代表命令行参数的数量、argv代表命令函参数的值、pxymnh代表指定的选项
	optret = getopt(argc,argv,"pxymnh");
	while( optret != -1 ) {
//			printf(" first in getpara: %s\n",argv[optind]);
        	switch( optret ) {
            // 处理源端口、确定使用的协议类型 controlled_protocol用来识别哪一个协议
        	case 'p':
        		if (strncmp(argv[optind], "ping",4) == 0 )
					controlled_protocol = 1;
				else if ( strncmp(argv[optind], "tcp",3) == 0  )
					controlled_protocol = 6;
				else if ( strncmp(argv[optind], "udp",3) == 0 )
					controlled_protocol = 17;
				else {
					printf("Unkonwn protocol! please check and try again! \n");
					exit(1);
				}
        		break;
         case 'x':   //获取命令行参数中指定的源 IP 地址，并将其转换为可用于防火墙规则中的格式
                     // 以便在防火墙规则中设置针对该源 IP 地址的控制策略。
                     // struct in_addr是结构体
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_saddr) == 0){
					printf("Invalid source ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'y':   //获取目标的的ip地址
				if ( inet_aton(argv[optind], (struct in_addr* )&controlled_daddr) == 0){
					printf("Invalid destination ip address! please check and try again! \n ");
					exit(1);
				}
         	break;
         case 'm':   //获取目标的端口
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_srcport = htons(tmpport);
         	break;
        case 'n':   //获取源端口
				tmpport = atoi(argv[optind]);
				if (tmpport == 0){
					printf("Invalid source port! please check and try again! \n ");
					exit(1);
				}
				controlled_dstport = htons(tmpport);
         	break;
         case 'h':   /* fall-through is intentional */
         case '?':
         	display_usage(argv[0]);
         	exit(1);;
                
         default:
				printf("Invalid parameters! \n ");
         	display_usage(argv[0]);
         	exit(1);;
        	}
        // getopt每次调用会返回下一个参数
		optret = getopt(argc,argv,"pxymnh");
	}
}

int main(int argc, char *argv[]){
	char controlinfo[32];
	int controlinfo_len = 0;
	int fd;
	struct stat buf;
	// argc代表选项的数量
    // controlinfo_len代表控制信息的长度
	if (argc == 1) 
		controlinfo_len = 0; //取消防火墙
	else if (argc > 1){
		getpara(argc, argv);
		*(int *)controlinfo = controlled_protocol;
		*(int *)(controlinfo + 4) = controlled_saddr;
		*(int *)(controlinfo + 8) = controlled_daddr;
		*(int *)(controlinfo + 12) = controlled_srcport;
		*(int *)(controlinfo + 16) = controlled_dstport;
		controlinfo_len = 20;
	}
	
//	printf("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);
 //查询/dev/controlinfo 的状态,若无则创建
 //mknod创建设备字符文件
	if (stat("/dev/controlinfo",&buf) != 0){
		if (system("mknod /dev/controlinfo c 124 0") == -1){
			printf("Cann't create the devive file ! \n");
			printf("Please check and try again! \n");
			exit(1);
		}
	}
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
