//#define __KERNEL__
//#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>


#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/time64.h>



#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#define MATCH		1
#define NMATCH	0

int enable_flag = 0;

struct nf_hook_ops myhook;	//Netfilter 框架中定义的结构体，用于注册和管理钩子函数。它包含了一些字段和回调函数，用于指定钩子函数的行为和属性。

/**保存真正使用的规则信息*/
unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;

//时间控制信息
int controlled_time_flag=0; //0表示时间判断功能关闭
unsigned int  controlled_time_begin=0;  
unsigned int controlled_time_end=0;  

//网络接口
int controlled_interface=0;

//icmp报文类型
int icmp_type[9]={0,0,0,0,0,0,0,0,0};
/*
0: 回显应答报文（Echo Reply）：宏定义 ICMP_ECHOREPLY，值为 0。
1: 回显请求报文（Echo Request）：宏定义 ICMP_ECHO，值为 8。
2: 目标不可达报文（Destination Unreachable）：宏定义 ICMP_DEST_UNREACH，值为 3。
3: 超时报文（Time Exceeded）：宏定义 ICMP_TIME_EXCEEDED，值为 11。
4: 参数问题报文（Parameter Problem）：宏定义 ICMP_PARAMETERPROB，值为 12。
5: 源抑制报文（Source Quench）：宏定义 ICMP_SOURCE_QUENCH，值为 4。
6: 重定向报文（Redirect）：宏定义 ICMP_REDIRECT，值为 5。
7: 时间戳请求报文（Timestamp Request）：宏定义 ICMP_TIMESTAMP，值为 13。
8: 时间戳应答报文（Timestamp Reply）：宏定义 ICMP_TIMESTAMPREPLY，值为 14。
*/
struct KeyValuePair {
    int key;
    int value;
};
struct KV_interface{
	int key;
	char value[10];
};
struct KeyValuePair icmp_type_reflection[9]={
    {0,0},
    {1,8},
    {2,3},
    {3,11},
    {4,12},
    {5,4},
    {6,5},
    {7,13},
    {8,14}
};
struct KV_interface interface_available[2]={
	{1,"ens33"},
	{2,"lo"}
};
struct sk_buff *tmpskb;
struct iphdr *piphdr;

/*检查端口号是否匹配*/
int port_check(unsigned short srcport, unsigned short dstport){
	if ((controlled_srcport == 0 ) && ( controlled_dstport == 0 ))
		return MATCH;
	if ((controlled_srcport != 0 ) && ( controlled_dstport == 0 ))
	{
		if (controlled_srcport == srcport)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport == 0 ) && ( controlled_dstport != 0 ))
	{
		if (controlled_dstport == dstport)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

/*检测IP地址是否匹配，若匹配返回MATCH并丢弃网络包*/
int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))	//未设置IP地址
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

// ICMP协议检查函数
int icmp_check(void){
	struct icmphdr *picmphdr;	//struct icmphdr 是定义在 <linux/icmp.h> 头文件中的结构体，用于表示 ICMP（Internet Control Message Protocol）报文头部的信息。
//  	printk("<0>This is an ICMP packet.\n");
   picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));	//将该指针指向 ICMP 报文数据的位置
	//printk("icmptype: %d",picmphdr->type);
	for(int i=0;i<9;i++){
	//printk("icmp[%d]: %d",i,icmp_type[i]);
        if(picmphdr->type==(icmp_type_reflection[i]).value &&icmp_type[(icmp_type_reflection[i]).key]==1 ){
            if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
			}
        }
    
    }
    return NF_ACCEPT;
}


int tcp_check(void){
	struct tcphdr *ptcphdr;
//   printk("<0>This is an tcp packet.\n");
   ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
	 	printk("A TCP packet is denied! \n");
		return NF_DROP;
	}
	else
      return NF_ACCEPT;
}

int udp_check(void){
	struct udphdr *pudphdr;
//   printk("<0>This is an udp packet.\n");
   pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
	 	printk("A UDP packet is denied! \n");
		return NF_DROP;
	}
	else
      return NF_ACCEPT;
}

//返回0表示时间判断功能关闭 或当前时间符合规则
int time_check(struct tm *tm){
    if(controlled_time_flag==0) return 0;
    else if(controlled_time_flag==1){
        int current_mins=(8+tm->tm_hour)*60+tm->tm_min;

        if(current_mins>controlled_time_begin && current_mins<controlled_time_end){
			printk("Access is denied at this time!\n");
            printk("current time: %d\n",current_mins);
            printk("control time: %d ~ %d\n",controlled_time_begin,controlled_time_end);
			return 1;
		}
        else return 0;
    }
    else return 0;
}


int net_interface_check(struct sk_buff *skb,const struct nf_hook_state *state){

	if(controlled_interface==0)return 0;	//对接口无要求直接返回

	struct net_device *dev_crl;
    unsigned char *controlled_mac_addr;
	
	//获取网络包的MAC
    struct net_device *dev = skb->dev;
    unsigned char *mac_addr = dev->dev_addr;

	// 获取指定的网络接口
	const char* interface_con =(interface_available[controlled_interface-1]).value;
    dev_crl = dev_get_by_name(&init_net, interface_con);  

	

    // 打印MAC地址
    printk("packet MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);



    if (dev_crl) {
        // 获取 MAC 地址的指针
        controlled_mac_addr = dev_crl->dev_addr;

        // 打印 MAC 地址
        printk("controlled MAC address：%pM\n", controlled_mac_addr);
        dev_put(dev_crl);
    } else {
        printk("Unable to get network card device!\n");
    }


	int result = memcmp(mac_addr, controlled_mac_addr, 6);
	if(result==0)return 0;
	else return 1;


}

/*unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
/*网络钩子函数 hook_func，用于网络数据包过滤和处理*/
unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
	
	
	if (enable_flag == 0)	//网络过滤器被禁用，返回NF_ACCEPT表示接受该数据包
		return NF_ACCEPT;
   	tmpskb = skb;	//将数据包传给全局变量
	piphdr = ip_hdr(tmpskb);	//获取IP报文头部的指针
	
	//检查网络接口
	if(net_interface_check(skb,state)==1){
		printk("The current network interface is disabled!\n");
		return NF_DROP;
	}
    //获取时间
    struct timespec64 ts;
    struct tm time_info;
    ktime_get_real_ts64(&ts);  // 获取当前系统时间
    time64_to_tm(ts.tv_sec, 0, &time_info);  // 将时间转换为本地时间

    if(time_check(&time_info)==1)return NF_DROP;    //判断时间是否符合规则

	if(piphdr->protocol != controlled_protocol)
      		return NF_ACCEPT;
	
	
	if (piphdr->protocol  == 1)  //ICMP packet
	{
		printk("icmp\n");
		return icmp_check();
	}
	else if (piphdr->protocol  == 6) //TCP packet
	{
		printk("tcp\n");
		return tcp_check();
	}
	else if (piphdr->protocol  == 17) //UDP packet
	{
		printk("udp\n");
		return udp_check();
	}
	else
	{
		printk("Unkonwn type's packet! \n");
		return NF_ACCEPT;
	}
}

static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];
	char *pchar;

	pchar = controlinfo;

	if (len == 0){
		enable_flag = 0;
		return len;
	}

	/*函数调用了 copy_from_user 函数，它用于将用户空间的数据复制到内核空间的缓冲区中。
	参数 controlinfo 是目标缓冲区的地址，buf 是源数据的地址，len 是要复制的数据长度。*/
	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	controlled_protocol = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_saddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_daddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_srcport = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_dstport = *(( int *) pchar);
    pchar = pchar + 4;
    controlled_time_flag = *(( int *) pchar);
    pchar = pchar + 4;
    controlled_time_begin = *(( int *) pchar);
    pchar = pchar + 4;
    controlled_time_end = *(( int *) pchar);
    for(int i=0;i<9;i++){
        pchar = pchar + 4;
        icmp_type[i]=*(( int *) pchar);
    }
    pchar = pchar + 4;
    controlled_interface=*(( int *) pchar);


	enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d; Time: flag = %d and %d ~ %d",
     controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport,
     controlled_time_flag,controlled_time_begin,controlled_time_end);
    printk("rejected icmp type: ");
    for(int i=0;i<9;i++){
        if(icmp_type[i]==1){
            printk(" %d",i+1);
        }
    }
    printk("controlled interface %d",controlled_interface);
    
	return len;
}

//struct file_operations 是 Linux 内核中定义的结构体，用于描述设备文件的操作函数集合。通过初始化该结构体的成员，可以指定设备文件的操作函数。
struct file_operations fops = {
	.owner=THIS_MODULE,	//用于指定该设备文件操作函数集合所属的模块。THIS_MODULE 是一个宏，表示当前模块自身
	.write=write_controlinfo,//用于指定写操作的函数指针。write_controlinfo 是一个自定义的函数，用于处理设备文件的写操作。
};

//模块的初始化函数 initmodule，在加载模块时会被调用。
static int __init initmodule(void)
{
	int ret;
   printk("Init Module\n");	//内核日志输出初始化信息
   myhook.hook=hook_func;	//指定网络钩子函数
   myhook.hooknum=NF_INET_POST_ROUTING;	//指定钩子函数的钩子点，NF_INET_POST_ROUTING 表示在 IP 协议栈的后期处理阶段触发钩子函数。
   myhook.pf=PF_INET;	//指定协议族，PF_INET 表示 IPv4 协议族
   myhook.priority=NF_IP_PRI_FIRST;	//指定钩子函数的优先级，NF_IP_PRI_FIRST 表示最高优先级。

   nf_register_net_hook(&init_net,&myhook);	//向网络协议栈注册钩子函数。&init_net 表示网络命名空间，&myhook 是指向钩子函数结构体的指针。

   ret = register_chrdev(124, "/dev/controlinfo", &fops); 	// 向系统注册设备结点文件；
   																						//向系统注册设备节点文件。124 是设备号，"/dev/controlinfo" 是设备文件路径，
																						//&fops 是设备文件的操作函数集合。
   if (ret != 0) printk("Can't register device file! \n");	//注册失败

   return 0;
}

//卸载模块时会被调用
static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);

	unregister_chrdev(124, "controlinfo");	 // 向系统注销设备结点文件
        printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");

