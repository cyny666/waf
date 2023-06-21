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

#define MATCH	1 // 表示符合要求
#define NMATCH	0  //not match

int enable_flag = 0;

struct nf_hook_ops myhook;

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;

struct sk_buff *tmpskb;
struct iphdr *piphdr;
// 检查port是否正确
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

// 检查ip是否正确
int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
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
// 过滤icmp（ping）协议
int icmp_check(void){
	struct icmphdr *picmphdr;
//  	printk("<0>This is an ICMP packet.\n");
// picmphdr 变量就指向了 ICMP 报文头部的位置
   picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));
// picmphdr->type 是否等于 0，如果是，则表示这是一个回显请求（ICMP Echo Request）报文，需要进行进一步处理。
	if (picmphdr->type == 0){
			if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
                //如果匹配，表示此 ICMP 报文需要被禁止，代码使用 printk() 函数输出一条日志信息，并返回 NF_DROP，表示将数据包丢弃。
			}
	}
    //如果 ICMP 报文的类型字段等于 8，表示这是一个回显应答（ICMP Echo Reply）报文
	if (picmphdr->type == 8){
			if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH){
			 	printk("An ICMP packet is denied! \n");
				return NF_DROP;
			}
	}
    return NF_ACCEPT;
}
//过滤tcp协议
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
//过滤udp协议
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

/*unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
*/
unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
//如果enable_flag=0表示防火墙被禁用
	if (enable_flag == 0)
		return NF_ACCEPT;
    //tmpskb用于存储当前处理的数据包
    //piphdr 变量用于存储数据包的 IP 报文头部
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);
 //协议类型
	if(piphdr->protocol != controlled_protocol)
      		return NF_ACCEPT;

	if (piphdr->protocol  == 1)  //ICMP packet
		return icmp_check();
	else if (piphdr->protocol  == 6) //TCP packet
		return tcp_check();
	else if (piphdr->protocol  == 17) //UDP packet
		return udp_check();
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

	enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);
	return len;
}


struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};


static int __init initmodule(void)
{
	int ret;
   printk("Init Module\n");
   myhook.hook=hook_func;
   myhook.hooknum=NF_INET_POST_ROUTING;
   myhook.pf=PF_INET;
   myhook.priority=NF_IP_PRI_FIRST;

   nf_register_net_hook(&init_net,&myhook);

   ret = register_chrdev(124, "/dev/controlinfo", &fops); 	// ��ϵͳע���豸����ļ�
   if (ret != 0) printk("Can't register device file! \n");

   return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);

	unregister_chrdev(124, "controlinfo");	 // ��ϵͳע���豸����ļ�
        printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
