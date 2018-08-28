#include <stdio.h>
#include <string.h>
#include <stdlib.h>  
#include <unistd.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <errno.h>  
#include <netdb.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <stdint.h>
//底层操作
#include "defAndTools.h"
//本地服务器
#include "localServer.h"

int main(int argc, char *argv[]) 
{ 
	//容错
	for (int i=1;i<=(argc-1)/2;i++)
		if (strTypeToCode(argv[2*i])==0)
			{
				printf("类型错误！\n");
				exit(0);
			}
	
	//①连接本地服务器 初始化TCP连接
	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	//发送缓冲和接收缓冲
	char sendbuf[512];    
	char recvbuf[512];
	//定义缓冲区指示下标
	int sendBufferPointer=0;
	int recvBufferPointer=0;
	//清空缓冲区
	memset(sendbuf,0,512);
	memset(recvbuf,0,512);
	
	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(SERVER_PORT);
	serverAddr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);
	//连接服务器
	if(connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr))==-1)
		printf("连接失败\n");
	printf("发送信息：\n");
	
	//②根据输入内容，准备DNS包，并写入发送缓冲区
	//定义DNS头部
	struct DNS_Header *query_header;
	query_header = malloc(sizeof(DNS_HEAD));
	//调用函数，填写欲发送的DNS包的头部结构体
	unsigned short tag = create_tag(0,0,0,0,0,0,0,0);    
	//argc-1除2即为域名请求的个数，因为每个域名参数后带一个类型
	create_query_header(query_header,999,tag,argc/2,0x0000,0x0000,0x0000);
	//将头部写入缓冲区
	encode_header(query_header,sendbuf,&sendBufferPointer);
	//打印生成的头部
	print_header(query_header);
	
	//根据运行参数生成一个或多个请求部分并写入缓冲区                         
	for(int i=1;i<=(argc-1)/2;i++) 
	{
		//填写DNS请求结构，argv[2*i]字符串对应的类型
		unsigned short qtype = strTypeToCode(argv[2*i]);    
		unsigned short qclass = 0x0001;  
		
		struct DNS_Query *query_section;
		query_section = malloc(sizeof(DNS_QUERY));
		create_query_section(query_section,argv[2*i-1],qtype,qclass);
		encode_query_section(query_section,sendbuf,&sendBufferPointer);	
		print_query_section(query_section);
	}
	
	//③向本地服务器发包
	//发送已准备好的在缓冲区的数据,包总长度即为当下发送缓冲区指针下标
	unsigned short length = htons(sendBufferPointer);
	//对于TCP连接，必须先发送一个DNS包总长度，否则wireshark不会识别！
	send(clientSocket,&length,2,0);
	send(clientSocket, sendbuf, sendBufferPointer, 0);
	
	//④根据请求数量收包,有多少个请求就会收到多少个DNS包
	for(int k=0;k<query_header->queryNum;k++)
	{
		unsigned short recv_length;
		recv(clientSocket,&recv_length,2,0);
		recv_length = ntohs(recv_length);
		int dataNum = recv(clientSocket, recvbuf, recv_length, 0);
	
		//⑤处理接收到缓冲区的DNS包,从中抽取出需要返还给用户的数据
		//构造DNS包头部，从缓冲区读取并填充DNS头部	
		struct DNS_Header *recv_header;
		recv_header = malloc(sizeof(DNS_HEAD));
		decode_header(recv_header,recvbuf,&recvBufferPointer);
		printf("[回复： %d]\n",k+1);
		print_header(recv_header);	
		struct DNS_RR *recv_answer,*recv_add;
		//标准回复只可能在answer和addition有值，所以只需要考虑读这两个部分
		for(int i=0;i<recv_header->answerNum;i++)
		{
			//读取解析打印一个回应部分
			recv_answer = NULL;
			recv_answer = malloc(sizeof(DNS_ResouceRecord));
			decode_resource_record(recv_answer,recvbuf,&recvBufferPointer);
			print_resource_record(recv_answer);
		}
		for(int i=0;i<recv_header->addNum;i++)
		{
			//读取解析打印一个addition部分
			recv_add = NULL;
			recv_add = malloc(sizeof(DNS_QUERY));
			decode_resource_record(recv_add,recvbuf,&recvBufferPointer);
			print_resource_record(recv_add);
		}
		recvBufferPointer=0;
		memset(recvbuf,0,512);	
	}
	close(clientSocket);
}
