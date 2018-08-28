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
#include "localServer.h"

#define CACHEFILE "localCache.txt"
int isEnd(struct DNS_Header *header)
{
	if (header->authorNum!=0)
		return 0;
	return 1;
}

int main(int argc, char *argv[]) 
{
	//①设置监听
	int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	//发送缓冲区和接收缓冲区
	char sendbuf[512];
	char recvbuf[512]; 
	int sendBufferPointer=0;
	int recvBufferPointer=0;
	//初始化缓冲区
	memset(sendbuf,0,512);
	memset(recvbuf,0,512);
		
	//声明两个套接字sockaddr_in结构体，分别用于客户端和服务器 
	struct sockaddr_in server_addr;  
	struct sockaddr_in clientAddr;  
	int addr_len = sizeof(clientAddr);  
	
	int client;  
	//初始化服务器端的套接字
	bzero(&server_addr, sizeof(server_addr));  
	server_addr.sin_family = AF_INET;  
	server_addr.sin_port = htons(SERVER_PORT); 
	server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER_IP);  
	 
	//绑定套接字
	bind(serverSocket, (struct sockaddr *)&server_addr, sizeof(server_addr));
	//设置监听状态
	listen(serverSocket, 5);
	
	//②循环监听
	while(1)
	{
		printf("监听端口 ： %d\n",SERVER_PORT);
		//调用accept，进入阻塞状态，返回一个client套接字描述符
		client = accept(serverSocket, (struct sockaddr*)&clientAddr, (socklen_t*)&addr_len);
		printf("连接成功\n");
	
		struct sockaddr_in c;
		socklen_t cLen = sizeof(c);
		getpeername(client, (struct sockaddr*) &c, &cLen); 
		printf("请求端信息： %s : %d\n",inet_ntoa(c.sin_addr),ntohs(c.sin_port));	
		
		//对于TCP，先接收一个两字节的包长度
		unsigned short recv_length;
		recv(client,&recv_length,2,0);
		recv_length = ntohs(recv_length);
		
		//接收客户端发来的数据，recv返回值为接收字节数
		int dataNum = recv(client,recvbuf,recv_length,0);
					
		//③提取recvbuf，构建DNS包
		//构造DNS包头部，从缓冲区读取一个DNS头部
		struct DNS_Header *client_query_header;
		client_query_header = malloc(sizeof(DNS_HEAD));
		decode_header(client_query_header,recvbuf,&recvBufferPointer);
		printf("\n请求端信息：\n");
		print_header(client_query_header);
		
		//构造准备发送的DNS头部
		struct DNS_Header *query_header;
		query_header = malloc(sizeof(DNS_HEAD));
		memcpy(query_header,client_query_header,sizeof(DNS_HEAD));
		query_header->queryNum = 1;
		
		//④解析并处理请求
		//有多少个请求，就进行几次循环，每个循环完成一次系统运作
		for(int i=0;i<client_query_header->queryNum;i++)   
		{
			//读取解析一个请求部分
			struct DNS_Query *client_query_section;
			client_query_section = malloc(sizeof(DNS_QUERY));
			decode_query_section(client_query_section,recvbuf,&recvBufferPointer);
			printf("\n正在处理第 %d 个请求\n",i+1);
			print_query_section(client_query_section);
			
			//判断本地缓存中是否存在
			int findInCache = firstFindRR(client_query_section,CACHEFILE,sendbuf,&sendBufferPointer);
			
			if (findInCache==1)
			{
				printf("在本地缓存中找到记录，直接回复请求\n");
				goto findit;
			}

			//本地缓存不存在
			char UDPsendbuf[512];
			char UDPrecvbuf[512]; 
			int UDPsendBufferPointer=0;
			int UDPrecvBufferPointer=0;
			memset(UDPsendbuf,0,512);
			memset(UDPrecvbuf,0,512);
			
			//直接将从客户端接受收的包写入缓冲区
			printf("\n发送给根服务器的请求：\n");
			encode_header(query_header,UDPsendbuf,&UDPsendBufferPointer);
			print_header(query_header);
			encode_query_section(client_query_section,UDPsendbuf,&UDPsendBufferPointer);
			print_query_section(client_query_section);
			
			//定义用于接收的结构。由于根服务器必然不可能返回最终结果，所以不需要构造answer
			struct DNS_Header *recv_header;
			struct DNS_RR *recv_answer,*recv_authority,*recv_additional;
			recv_header = malloc(sizeof(DNS_HEAD));
			recv_authority = malloc(sizeof(DNS_ResouceRecord));
			recv_additional = malloc(sizeof(DNS_ResouceRecord));
			
			//与根服务器建立UDP连接
			int sockfd=socket(AF_INET,SOCK_DGRAM,0);
			struct sockaddr_in addr;
			addr.sin_family =AF_INET;
			addr.sin_port =htons(SERVER_PORT);
			addr.sin_addr.s_addr=inet_addr(ROOT_SERVER_IP);	
			
			bind(sockfd,(struct sockaddr*)&addr,sizeof(addr));
			
			//发送  
			sendto(sockfd,UDPsendbuf,UDPsendBufferPointer,0,(struct sockaddr*)&addr,sizeof(addr));
			
			//接收回复
			socklen_t len=sizeof(addr);
			recvfrom(sockfd,UDPrecvbuf,sizeof(UDPrecvbuf),0,(struct sockaddr*)&addr,&len);   
			
			//断开
			close(sockfd); 
			
			printf("\n收到根服务器的回复：\n");
			//从接收缓冲区解析并构造包结构然后打印
			decode_header(recv_header,UDPrecvbuf,&UDPrecvBufferPointer);
			print_header(recv_header);
			 
			decode_resource_record(recv_authority,UDPrecvbuf,&UDPrecvBufferPointer);
			print_resource_record(recv_authority);
			decode_resource_record(recv_additional,UDPrecvbuf,&UDPrecvBufferPointer);
			print_resource_record(recv_additional);
			
			//重置缓冲区
			UDPsendBufferPointer=0;
			UDPrecvBufferPointer=0;
			memset(UDPsendbuf,0,512);
			memset(UDPrecvbuf,0,512);
			
			//用于计数本次循环是第几级服务器发来的
			int count=0;
			while(isEnd(recv_header)==0)  
			{
				count++;
				//向下一个服务器建立UDP连接
				int sockfm=socket(AF_INET,SOCK_DGRAM,0);
				struct sockaddr_in addr;
				addr.sin_family =AF_INET;
				addr.sin_port =htons(SERVER_PORT);
				addr.sin_addr.s_addr=inet_addr(recv_additional->rdata);		
				//recv_additional->rdata即保存着下一个服务器的IP
				
				bind(sockfm,(struct sockaddr*)&addr,sizeof(addr));
				
				//重置缓冲区和结构
				UDPsendBufferPointer=0;
				UDPrecvBufferPointer=0;
				memset(UDPsendbuf,0,512);
				memset(UDPrecvbuf,0,512);
				free(recv_header);     recv_header = NULL;           
				free(recv_authority);  recv_authority = NULL;
				free(recv_additional); recv_additional = NULL;
				
				//直接将从客户端接受收的请求写入发送缓冲区
				printf("\n发送给 %d级 服务器的请求：\n",count);
				encode_header(query_header,UDPsendbuf,&UDPsendBufferPointer);
				print_header(query_header);
				encode_query_section(client_query_section,UDPsendbuf,&UDPsendBufferPointer);
				print_query_section(client_query_section);
				
				//发送
				sendto(sockfm,UDPsendbuf,UDPsendBufferPointer,0,(struct sockaddr*)&addr,sizeof(addr));
				
				//接收回复
				len=sizeof(addr);
				recvfrom(sockfm,UDPrecvbuf,sizeof(UDPrecvbuf),0,(struct sockaddr*)&addr,&len);
				
				//断开连接
				close(sockfm); 
				
				//开始处理
				printf("\n收到 %d级 服务器发来的回复：\n",count);	
				
				recv_header = malloc(sizeof(DNS_HEAD));
				recv_answer = malloc(sizeof(DNS_ResouceRecord));
				recv_authority = malloc(sizeof(DNS_ResouceRecord));
				recv_additional = malloc(sizeof(DNS_ResouceRecord));
				
				decode_header(recv_header,UDPrecvbuf,&UDPrecvBufferPointer);
				print_header(recv_header);
				
				for(int j=0;j<recv_header->answerNum;j++){   
					decode_resource_record(recv_answer,UDPrecvbuf,&UDPrecvBufferPointer);
					print_resource_record(recv_answer);
				}
				
				for(int j=0;j<recv_header->authorNum;j++){  
					decode_resource_record(recv_authority,UDPrecvbuf,&UDPrecvBufferPointer);
					print_resource_record(recv_authority);
				}
				 
				for(int j=0;j<recv_header->addNum;j++){      
					decode_resource_record(recv_additional,UDPrecvbuf,&UDPrecvBufferPointer);
					print_resource_record(recv_additional);
				}			
			}
			
			//UDP请求的循环结束，此时构造得到的结构体已经得到该次请求目标结果，且已经在循环中打印  
			//将从最终结果服务器返回来的结构写入发送缓冲区，本次循环结束
			encode_header(recv_header,sendbuf,&sendBufferPointer);
			for(int j=0;j<recv_header->answerNum;j++){
				encode_resource_record(recv_answer,sendbuf,&sendBufferPointer);
				//将结果写入cache
				addRRToCache(recv_answer,"localCache.txt");
			}
			for(int j=0;j<recv_header->authorNum;j++){
				encode_resource_record(recv_authority,sendbuf,&sendBufferPointer);
				addRRToCache(recv_authority,"localCache.txt");
			}
			for(int j=0;j<recv_header->addNum;j++){
				encode_resource_record(recv_additional,sendbuf,&sendBufferPointer);
				addRRToCache(recv_additional,"localCache.txt");
			}
			
		findit:;
			//⑤发送缓冲
			//发送已准备好的在缓冲区的数据,包总长度即为当下发送缓冲区指针下标
			unsigned short send_length = htons(sendBufferPointer);
			send(client,&send_length,2,0);
			send(client, sendbuf, sendBufferPointer, 0);   
			//一个请求的解析与回答发送结束,清空发送缓冲区与指针，准备进行下一次发送
			sendBufferPointer=0;
			memset(sendbuf,0,512);	
		}
		
		//对一个客户端的所有请求解析结束
		close(client);
		recvBufferPointer=0;
		memset(recvbuf,0,512);
		printf("连接关闭\n");
		printf("===================================\n\n");
	} 
}

	
	
