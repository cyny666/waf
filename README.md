- 添加的选项：b、e、t、i

  - 选项b：禁止访问时间段的开始时间

    输入格式`-b xx:xx`；

    例：`-b 09:35`

  - 选项e：禁止访问时间段的结束时间

    输入格式`-e xx:xx`；

    例：`-e 19:35`

  - 选项t：禁止访问的ICMP网络包的子类型

    输入格式`-p icmp -t x`，x为1~9，对应不同ICMP报文子类型：

    1: 回显应答报文（Echo Reply）

    2: 回显请求报文（Echo Request）
  
    3: 目标不可达报文（Destination Unreachable）
  
    4: 超时报文（Time Exceeded）
  
    5: 参数问题报文（Parameter Problem）
  
    6: 源抑制报文（Source Quench）
  
    7: 重定向报文（Redirect）
  
    8: 时间戳请求报文（Timestamp Request）
  
    9: 时间戳应答报文（Timestamp Reply）
  
  - 选项i ：禁止访问的网络接口
  
    输入格式`-i x`，x为1或2，分别对应"ens33"和“lo"
  
- 可以添加多条规则

  - 通过结构体实现可以添加30条规则: `struct Rule rules_array[30];    //存储规则信息的数组`
  - 如何添加规则：依次输入`./cinfigure -选项 参数`以添加1条规则

- 可以删除规则

  - 通过输入`.\configure -d index`删除指定序号的规则，其中index从1开始

