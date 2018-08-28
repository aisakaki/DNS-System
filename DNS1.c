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

#include "defAndTools.h"

#define SERVER_IP "127.0.0.4"
#define RRFILE "RRL1.txt"

int main(int argc, char *argv[]) 
{
	char sendbuf[512];
	char recvbuf[512]; 
	int sendBufferPointer=0;
	int recvBufferPointer=0;
	memset(sendbuf,0,512);
	memset(recvbuf,0,512);
	
	int sockfd=socket(AF_INET,SOCK_DGRAM,0);
	struct sockaddr_in addr;
	addr.sin_family =AF_INET;
	addr.sin_port =htons(SERVER_PORT);
	addr.sin_addr.s_addr=inet_addr(SERVER_IP);   
	
	bind(sockfd,(struct sockaddr*)&addr,sizeof(addr));
	struct sockaddr_in cli;
	socklen_t len=sizeof(cli);
	while(1)   
	{
		recvfrom(sockfd,recvbuf,sizeof(recvbuf),0,(struct sockaddr*)&cli,&len);
		printf("\n收到本地服务器请求：\n");
		//读取，构造包，得到需要找的域名和类型
		struct DNS_Header *recv_header;
		recv_header = malloc(sizeof(DNS_HEAD));
		decode_header(recv_header,recvbuf,&recvBufferPointer);
		print_header(recv_header);	
		
		struct DNS_Query *query_section;
		query_section = malloc(sizeof(DNS_QUERY));
		decode_query_section(query_section,recvbuf,&recvBufferPointer);
		print_query_section(query_section);      
		
		//开始查找与写缓冲
		//调用初次搜索函数
		int over = firstFindRR(query_section,RRFILE,sendbuf,&sendBufferPointer);
		
		//第一次搜索没有查到结果,开始查询下一个该去哪个服务器
		if(over==0) 
		{
			printf("\n本服务器没有找到\n");
			loopFindNS(query_section,RRFILE,sendbuf,&sendBufferPointer);
		}
		//发送
		sendto(sockfd,sendbuf,sendBufferPointer,0,(struct sockaddr*)&cli,len);  
		//缓冲区重置
		sendBufferPointer=0;    
		recvBufferPointer=0;
		memset(sendbuf,0,512);
		memset(recvbuf,0,512);
	}
	close(sockfd);
}
