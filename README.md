# ttm

TTM模块用来支持服务端应用程序获取客户端真实源IP。客户端的数据包经过高防IP转发后，会将数据包的源地址和端口号，改成高防IP回源的地址和端口号。
如果高防IP转发报文时将客户端真实源IP和端口号添加到TCP报文的tcp option字段。源站加载TTM模块后，TTM模块通过Hook Linux内核TCP协议栈的相关函数，
从TCP报文的tcp option字段中解析出客户端真实源IP和端口号。服务端应用程序调用getpeername或者accept获取到的就是客户端真实源IP和端口号。

## 编译

1. 安装编译环境
```
yum -y install gcc kernel-headers kernel-devel
```
2. 编译TTM模块，编译后会在当前目录生成bce_ttm.ko文件
```
 make
```
3. 加载TTM模块
```
mv bce_ttm.ko /lib/modules/$(uname -r)/kernel/net/ipv4/
insmod /lib/modules/$(uname -r)/kernel/net/ipv4/bce_ttm.ko
```  

## 测试

可以使用testtools目录下的ttm_test.c程序进行测试，测试步骤如下：
1. 下载编译libpcap
```
wget -c http://www.tcpdump.org/release/libpcap-1.5.3.tar.gz
tar -zvxf libpcap-1.5.3.tar.gz 
cd libpcap-1.5.3/
./configure
make && make install
``` 
> **注意：**
> 如果安装libpcap失败，可能是缺少依赖库bison, flex，执行yum -y install bison flex

2. 编译ttm_test程序
```
gcc ttm_test.c -o ttm_test -lpcap
```
3. 配置iptables规则，丢掉被测机器的报文，不让它送入内核，否则对测试会有干扰
 ```
iptables -A INPUT -p tcp -s x.x.x.x --sport 80 -j DROP
```
4. 执行ttm_test测试程序
 ```
./ttm_test -e eth0 -s x.x.x.x -d x.x.x.x -p 80
```
> **注意：**
> 其中-s后加的是源ip，-d后加的是目的ip，-e后加的是发送报文的网卡，可以通过执行./ttm_test -h查看参数指导