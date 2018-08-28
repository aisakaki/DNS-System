#include <stdio.h>
#include <string.h>
#include <arpa/inet.h> 
#include <stdlib.h>

#define MAX_SIZE_OF_DOMAIN 100
#define SERVER_PORT 53
#define ROOT_SERVER_IP "127.0.0.3"

//用于储存域名方便处理的全局变量
char domain_temp[MAX_SIZE_OF_DOMAIN];
typedef struct DNS_Header
{
	unsigned short id;       //16位的消息ID标示一次正常的交互，该ID由消息请求者设置，消息响应者回复请求时带上该ID。
	unsigned short tag;      //tag要拆，并单独写一个生成tag函数
	unsigned short queryNum; //标示请求部分的条目数 
	unsigned short answerNum;//标示响应部分的资源记录数。如果响应消息中没有记录，则设置为0
	unsigned short authorNum;//标示权威部分的域名服务器资源记录数。如果响应消息中没有权威记录，则设置为0
	unsigned short addNum;   //标示额外部分的资源记录数。
}DNS_HEAD;

typedef struct DNS_Query
{
	char *name;              //请求的域名。
	unsigned short qtype;    //记录的类型 [A:0x0001] [NS:0x0002] [CNAME:0x0005] [MX:0x000F]
	unsigned short qclass;   //请求的资源记录的类型 一般为[IN:0x0001]
}DNS_QUERY;

typedef struct DNS_RR  
{
	char *name;   
	unsigned short type;     //请求的域名
	unsigned short _class;   //响应的资源记录的类型 一般为[IN:0x0001]
	unsigned int ttl;        //该资源记录被缓存的秒数。
	unsigned short data_len; //RDATA部分的长度
	unsigned short pre;      //MX特有的优先级 Preference
	char *rdata;	         //[A:32位的IP地址（4字节）] [CNAME/NS/MX:域名]
}DNS_ResouceRecord;

typedef struct tag
{
	unsigned short qr;       //[1]标示该消息是请求消息（该位为0）还是应答消息（该位为1）
	unsigned short opcode;   //[4]0  QUERY。标准查询
	unsigned short aa;       //[1]只在响应消息中有效。该位标示响应该消息的域名服务器是该域中的权威域名服务器。因为Answer Section中可能会有很多域名
	unsigned short tc;       //[1]标示这条消息是否因为长度超过UDP数据包的标准长度512字节，如果超过512字节，该位被设置为1
	unsigned short rd;       //[1]是否递归查询。1为递归查询
	unsigned short ra;       //[1]在响应消息中清除并设置。标示该DNS域名服务器是否支持递归查询。
	unsigned short z;        //[3] 冗余res 0
	unsigned short rcode;    //[4] 0  成功的响应
}TAG;

/***********************缓冲区操作和工具***************************/
/*此函数用于向buffer中写入8bit数据
 * *buffer:指向缓冲区
 * *bufferPointer:目前已写入的缓冲区最新一位的下一位
 * 以下put16bits put32bits同理
 */
void put1Byte(char *buffer,int *bufferPointer, char value)
{
	//调整value为网络字节序
	value = htons(value);
	//void *memcpy(void *dest, void *src, unsigned int count);
	//用于 把资源内存（src所指向的内存区域） 拷贝到目标内存（dest所指向的内存区域）,count为拷贝区域大小.
	//buffer为缓冲区首地址，bufferPointer为缓冲区已写入下标，此函数参数为指向这两个量的指针，通过传递地址来实现主函数与子函数的实参传递。
	//value为欲写入缓冲区的数据(value为8bit)
	memcpy(buffer + *bufferPointer,&value,1);
	//缓冲区已写入下标向后移动，使其指向下一次写入时应该写入的位置,*bufferPointer为指针bufferPointer所指地址的内容
	*bufferPointer += 1;	
}
void put2Bytes(char *buffer,int *bufferPointer, unsigned short value)
{
	value = htons(value);
	memcpy(buffer + *bufferPointer,&value,2);
	*bufferPointer += 2;	
}
void put4Bytes(char *buffer,int *bufferPointer, unsigned int value)
{
	value = htons(value);
	memcpy(buffer + *bufferPointer,&value,4);
	*bufferPointer += 4;	
}
//将变长字符串str写入buffer  
void putDomainName(char *buffer,int *bufferPointer, char *str)
{
	memcpy(buffer + *bufferPointer,str,strlen(str)+1); //末尾0需要一起打印
	*bufferPointer += strlen(str)+1;
}
//从缓冲区取16个位
unsigned short get2Bytes(char *buffer,int *bufferPointer)
{
	unsigned short value;
	memcpy(&value,buffer + *bufferPointer,2);
	*bufferPointer += 2;
	
	return ntohs(value);  
}
unsigned int get4bits(char *buffer,int *bufferPointer)
{
	unsigned int value;
	memcpy(&value,buffer + *bufferPointer,4);
	*bufferPointer += 4;
	
	return ntohs(value);  
}
//读取变长字符串str 读取到0即停止 0即为'\0' 
//域名不考虑字节序问题 ，也不用考虑编码问题，都是一个字节一个字节读
void getDomainName(char *buffer,int *bufferPointer,int *lengthOfDomain)  
{   
	
	int valueWriting=0;
	while(buffer[*bufferPointer]!=0)  
	{        
		domain_temp[valueWriting] = buffer[*bufferPointer]; 
		valueWriting++;
		(*bufferPointer)++;
	}
	domain_temp[valueWriting] = 0; //末尾为0，写入字符串结束符，方便对字符数组进行字符串操作
	(*bufferPointer)++; //缓冲区读写下一位指针指示跳过末尾0
	*lengthOfDomain = valueWriting+1; //包含了末尾结束符 
	
}
//eg 3www6google3com0   
//生成域名编码
//一个UTF8 数字占1个字节。一个UTF8汉字占3个字节
void encode_domain(char* domain)           
{
	memset(domain_temp,0,MAX_SIZE_OF_DOMAIN);   
	int valueWriting=0;
	char *p,*q;
	q = domain;
	p = q;
	char count = 0;
	while(1)   
	{
		if((*p=='.')||(*p==0))
		{
			//第一位为count,写入字符串  
			*(domain_temp+valueWriting)=count;  //此处最后一位0的情况写入了 
			valueWriting += 1;
			//写入q开始，长度为count的字符串（长度为count)
			memcpy(domain_temp+valueWriting,q,count);
			valueWriting += count; 
			
			//计数清0
			count = 0;
			//如果未读到字符串末尾，将q移动到p+1的位置，重新开始下一轮
			if (*p=='.')
			{
				q=p+1;
				p = q;
			}else break;
		}else
		{
			p++;
			count++;
		}
	}
}
//解析编码的域名
void decode_domain(char* domain)
{
	memset(domain_temp,0,MAX_SIZE_OF_DOMAIN);
	int valueWriting = 0;
	char *p = domain;  
	int count = *p;
	while(count!=0)
	{
		for(int i=0;i<count;i++)
		{
			p += 1;
			domain_temp[valueWriting] = *p;
			valueWriting++;
		}
		if (*(p+1)!=0) 
		{
			domain_temp[valueWriting] = '.';
			valueWriting++;
		}
		p += 1;
		count = *p;
	}
	domain_temp[valueWriting]=0;
}

//OPCODE、Z、RCODE不用管，无论输入什么都为0。其他都是单位的
unsigned short create_tag(unsigned short qr,unsigned short opcode,unsigned short aa,unsigned short tc,unsigned short rd,unsigned short ra,unsigned short z,unsigned short rcode)
{
	unsigned short tag = 0;
	if (qr==1)  tag = tag | 0x8000;
	if (aa==1)  tag = tag | 0x0400;
	if (tc==1)  tag = tag | 0x0200;
	if (rd==1)  tag = tag | 0x0100;
	if (ra==1)  tag = tag | 0x0080;
	return tag;
}

//类型的名字与编码的转换
unsigned short strTypeToCode(char* type)
{
	if (strcmp(type,"A")==0) return 0x0001;
	if (strcmp(type,"NS")==0) return 0x0002;
	if (strcmp(type,"CNAME")==0) return 0x0005;
	if (strcmp(type,"MX")==0) return 0x000F;
	return 0;
}
char* codeTypeToStr(unsigned short num)
{
	if (num==0x0001) return "A";
	if (num==0x0002) return "NS";
	if (num==0x0005) return "CNAME";
	if (num==0x000F) return "MX";
	return "ERROR";
}

/***********************DNS头部操作***************************/
/*
 *此函数用于填充客户端发送请求的dns包的头部
 */
void create_query_header(struct DNS_Header *query_header,unsigned short id,unsigned short tag,unsigned short queryNum,unsigned short answerNum,unsigned short authorNum,unsigned short addNum)
{
	query_header->id = id;
	query_header->tag = tag;
	query_header->queryNum = queryNum;
	query_header->answerNum = answerNum;
	query_header->authorNum = authorNum;
	query_header->addNum = addNum;
}
/*此函数用于将已经填充好的dns头部结构体的成员依次写入buffer
 *  *header: 指向已填充好的dns头部结构体的指针
 *  *buffer: 指向缓冲区
 *  *bufferPointer: 目前已写入的缓冲区最新一位的下一位
 */
void encode_header(struct DNS_Header *header,char *buffer,int *bufferPointer)
{
	put2Bytes(buffer,bufferPointer,header->id);
	put2Bytes(buffer,bufferPointer,header->tag);
	put2Bytes(buffer,bufferPointer,header->queryNum);
	put2Bytes(buffer,bufferPointer,header->answerNum);
	put2Bytes(buffer,bufferPointer,header->authorNum);
	put2Bytes(buffer,bufferPointer,header->addNum);
}
void decode_header(struct DNS_Header *header,char *buffer,int *bufferPointer)
{
	header->id=get2Bytes(buffer,bufferPointer);
	header->tag=get2Bytes(buffer,bufferPointer);
	header->queryNum=get2Bytes(buffer,bufferPointer);
	header->answerNum=get2Bytes(buffer,bufferPointer);
	header->authorNum=get2Bytes(buffer,bufferPointer);
	header->addNum=get2Bytes(buffer,bufferPointer);
}
void print_header(struct DNS_Header *query_header)
{
	printf("[DNS HEADER]\n");
	printf("ID         :         %d\n",query_header->id);
	printf("TAG        :         0x%x\n",query_header->tag);
	printf("QueryNum   :         %d\n",query_header->queryNum);
	printf("AnswerNum  :         %d\n",query_header->answerNum);
	printf("AuthorNum  :         %d\n",query_header->authorNum);
	printf("AddNum     :         %d\n",query_header->addNum);
}

/***********************DNS请求部分操作***************************/
/*
 *生成DNS包的请求部分
 */
void create_query_section(struct DNS_Query *query_section,char* domain_name, unsigned short qtype, unsigned short qclass)
{
	int domain_length = strlen(domain_name);
	query_section->name = malloc(domain_length+1);
	memcpy(query_section->name,domain_name,domain_length+1);	
	
	query_section->qtype = qtype;
	query_section->qclass = qclass;	
}
/*
 *将已经填充好的dns的一个请求结构体的成员依次写入buffer(调用一次该函数只写入一个请求
 */
void encode_query_section(struct DNS_Query *query_section,char *buffer,int *bufferPointer)
{
	//先计算用decodeDomain得到字符串
	//再用strlen计算字符串长度为点语法name长度+2（头尾多了一个数字）
	//再发送 
	char *domain_name;
	int lengthOfEncodedDomain = strlen(query_section->name)+2;
	domain_name = malloc(lengthOfEncodedDomain);
	encode_domain(query_section->name);
	memcpy(domain_name,domain_temp,lengthOfEncodedDomain);
	putDomainName(buffer,bufferPointer,domain_name); 
	
	put2Bytes(buffer,bufferPointer,query_section->qtype);
	put2Bytes(buffer,bufferPointer,query_section->qclass);
}
/*
 *解析请求部分。解析即为将缓冲区的字节流提取，转码，生成对应的结构体
 */
void decode_query_section(struct DNS_Query *query_section,char *buffer,int *bufferPointer)
{
	//从缓冲区读出编码过的域名
	char* domain_name = malloc(MAX_SIZE_OF_DOMAIN); 
	memset(domain_name,0,MAX_SIZE_OF_DOMAIN);
	int lengthOfDomain=0;
	getDomainName(buffer,bufferPointer,&lengthOfDomain);
	memcpy(domain_name,domain_temp,lengthOfDomain);
	
	//解码域名
	decode_domain(domain_name);
	memcpy(domain_name,domain_temp,strlen(domain_name));  
	
	query_section->name = domain_name;
	query_section->qtype = get2Bytes(buffer,bufferPointer);
	query_section->qclass = get2Bytes(buffer,bufferPointer);
}

void print_query_section(struct DNS_Query *query_section)
{
	printf("[DNS QUERY]\n");
	printf("Name       :         %s\n",query_section->name);
	printf("Type       :         %s\n",codeTypeToStr(query_section->qtype));
	printf("Class      :         IN\n");
}

/***********************DNS RR操作和RR文件解析操作***************************/
//生成resource record记录
void create_resource_record(struct DNS_RR *resource_record,char* name, unsigned short type, unsigned short _class, unsigned int ttl, unsigned short pre,char *rdata) //data_len不用输入  
{
	//unsigned short pre为一个MX类型特有的优先级，定长，只有MX类型发送。
	int domain_length = strlen(name);
	//易错点：strlen只读到0但不包含0，所以为了把结束符也复制进去，长度要+1
	resource_record->name = malloc(domain_length+1);   
	memcpy(resource_record->name,name,domain_length+1);
	
	resource_record->type = type;
	resource_record->_class = _class;
	resource_record->ttl = ttl;       //data_len
	if (type==0x0001) resource_record->data_len=4;  //对于IP，长度为4 data_len是编码后的长度，length是非编码长度，注意
		else resource_record->data_len = strlen(rdata) + 2;      //对于域名，生成data_len包含末尾结束符（域名末尾结束符）
	
	//pre
	if (type==0x000F) {
		resource_record->pre = pre;
		resource_record->data_len += 2;  //对于邮件类型，由于有pre的存在，多占两个字节
	}
	
	//char* rdata
	int rdata_length = strlen(rdata);  //要加上末尾结束符
	resource_record->rdata = malloc(rdata_length+1);
	memcpy(resource_record->rdata,rdata,rdata_length+1);
}

//编码resource record记录，编码即为将结构体的内容编码，处理为字节流，写入缓冲区
void encode_resource_record(struct DNS_RR *resource_record,char *buffer,int *bufferPointer)
{
	char *domain_name;
	int lengthOfEncodedDomain = strlen(resource_record->name)+2;
	domain_name = malloc(lengthOfEncodedDomain);
	 
	encode_domain(resource_record->name);
	memcpy(domain_name,domain_temp,lengthOfEncodedDomain);
	
	putDomainName(buffer,bufferPointer,domain_name); 
	
	put2Bytes(buffer,bufferPointer,resource_record->type);
	put2Bytes(buffer,bufferPointer,resource_record->_class);
	put4Bytes(buffer,bufferPointer,resource_record->ttl);
	put2Bytes(buffer,bufferPointer,resource_record->data_len);   
	if (resource_record->type==0x000F) 
		put2Bytes(buffer,bufferPointer,resource_record->pre);
		
	//如果类型为A，发送的是IP，将IP写入缓冲区               
	if(resource_record->type == 0x0001)         
	{
		//不能调用get put函数，因为inet_addr自带字节序变换功能
		unsigned int rdata = inet_addr(resource_record->rdata);
		memcpy(buffer + *bufferPointer,&rdata,4);
		*bufferPointer += 4;
	
	}else{          
	//如果类型为MX、CNAME、NS
	//则发送的是域名，则调用域名编码
		char *rdata;
		int lengthOfEncodedDomain2 = strlen(resource_record->rdata)+2;
		rdata = malloc(lengthOfEncodedDomain2);
		encode_domain(resource_record->rdata);
		memcpy(rdata,domain_temp,lengthOfEncodedDomain2);   
		putDomainName(buffer,bufferPointer,rdata); 
	}
}

//解析resource record记录
void decode_resource_record(struct DNS_RR *resource_record,char *buffer,int *bufferPointer)
{
	//从缓冲区读出编码过的域名
	char* domain_name = malloc(MAX_SIZE_OF_DOMAIN); 
	memset(domain_name,0,MAX_SIZE_OF_DOMAIN);
	int lengthOfDomain=0;
	getDomainName(buffer,bufferPointer,&lengthOfDomain);
	memcpy(domain_name,domain_temp,lengthOfDomain);
	//解码域名
	
	decode_domain(domain_name);
	memcpy(domain_name,domain_temp,strlen(domain_name));  
	resource_record->name = domain_name;
	
	resource_record->type = get2Bytes(buffer,bufferPointer);
	resource_record->_class = get2Bytes(buffer,bufferPointer);
	resource_record->ttl = get4bits(buffer,bufferPointer);   
	resource_record->data_len = get2Bytes(buffer,bufferPointer);
	if (resource_record->type==0x000F) 
			resource_record->pre = get2Bytes(buffer,bufferPointer);
	
	//如果发送的是IP（类型为A），则读出IP 。 不能采用get put方法，因为inet_ntoa方法已经更换字节序
	if(resource_record->type == 0x0001)   
	{
		unsigned int rdata;
		memcpy(&rdata,buffer + *bufferPointer,4);
		*bufferPointer += 4;
		
		struct in_addr in;
		memcpy(&in, &rdata, 4);  
		
		resource_record->rdata = malloc(MAX_SIZE_OF_DOMAIN);
		char *temp =  inet_ntoa(in);
		memcpy(resource_record->rdata,temp,strlen(temp)+1);   //+1是为了包含末尾0    
	}else{
		//如果发送的是域名，则调用域名解码（类型为CNAME NS MX）
		//从缓冲区读出编码过的域名
		char* rdata = malloc(MAX_SIZE_OF_DOMAIN); 
		int lengthOfDomain2=0;
		getDomainName(buffer,bufferPointer,&lengthOfDomain2);
		memcpy(rdata,domain_temp,lengthOfDomain2);
		//解码域名
		decode_domain(rdata);
		memcpy(rdata,domain_temp,strlen(rdata));  
		resource_record->rdata = rdata;
	}
}

void print_resource_record(struct DNS_RR *resource_record)
{
	printf("[RESOURCE RECORD]\n");
	printf("Name       :         %s\n",resource_record->name);
	printf("Type       :         %s\n",codeTypeToStr(resource_record->type));
	printf("Class      :         IN\n");
	printf("TTL        :         %d\n",resource_record->ttl);
	printf("Data_Len   :         %d\n",resource_record->data_len);
	if (resource_record->type==0x000F) 
	printf("Preference :         %d\n",resource_record->pre);
	printf("IP|DOMAIN  :         %s\n",resource_record->rdata);
	printf("===================================\n");
}

//砍掉一个域名第一个.之前的部分,如果已经是最后一节，指向域名的指针指向NULL
void cut(char** domainPointer)  //这里传入的是 指向指向域名的指针的指针
{
	while(1)
	{
		(*domainPointer)++;
		if (**domainPointer=='.')
		{
			(*domainPointer)++;
			break;		
		}
		if (**domainPointer==0)
		{
			*domainPointer = NULL;
			break;
		}
	}
}

/***********************文件读写***************************/
//将RR写进cache文件里
void addRRToCache(struct DNS_RR *resource_record, char* cacheFile)
{
	FILE *RR = fopen(cacheFile, "a+");
	fprintf(RR,"%s         ",resource_record->name);
	fprintf(RR,"%d         ",resource_record->ttl);
	fprintf(RR,"IN         ");
	fprintf(RR,"%s         ",codeTypeToStr(resource_record->type));
	fprintf(RR,"%s\n",resource_record->rdata);
	fclose(RR);
}

//第一次在RR文件里扫描 （初次搜索函数）
//如果找到了，返回1，且encode进buffer
int firstFindRR(struct DNS_Query *query_section,char *RRDOCUMENT,char *buffer,int *bufferPointer)
{
	int over = 0;
	FILE *RR = fopen( RRDOCUMENT, "r" );
	//定义一个RR结构体用来储存从文件中读入的一条RR
	struct DNS_RR *fileRR;
	fileRR = malloc(sizeof(DNS_ResouceRecord));
	memset(fileRR,0,sizeof(DNS_ResouceRecord));
	fileRR->name=malloc(MAX_SIZE_OF_DOMAIN);  
	fileRR->rdata=malloc(MAX_SIZE_OF_DOMAIN);
	//第一次搜索
	while(fscanf(RR,"%s ",fileRR->name)!=EOF)   
	{
		fscanf(RR,"%d",&fileRR->ttl);
		char type[10],_class[10];
		fscanf(RR,"%s ",_class);
		fscanf(RR,"%s ",type);
		fileRR->type = strTypeToCode(type);
		fscanf(RR,"%s\n",fileRR->rdata);
		
		if((strcmp(query_section->name,fileRR->name)==0) && (query_section->qtype==fileRR->type))
		{
			printf("\n发送回复：\n");
			//生成answer RR
			create_resource_record(fileRR,fileRR->name, fileRR->type, 0x0001, fileRR->ttl, 0x0000,fileRR->rdata);
			//生成头
			struct DNS_Header *header;
			header = malloc(sizeof(DNS_HEAD));
			unsigned short tag = create_tag(1,0,1,0,0,0,0,0);
			if (strcmp(type,"MX")==0)   create_query_header(header,0x1235,tag,0,1,0,1);
				else create_query_header(header,999,tag,0,1,0,0);
			//将头和answer encode进buffer
			encode_header(header,buffer,bufferPointer);
			print_header(header);
			encode_resource_record(fileRR,buffer,bufferPointer);
			print_resource_record(fileRR);
			over=1;
			break;
		}
	}
	
	//读指针回到开头
	fseek(RR,0,0);
	//对于MX类型，特殊，需要再搜索一遍，搜索到的邮件服务器域名的IP，并写入addition RR中发送    
	if ((fileRR->type==0x000F)&&(over==1)) 
	{
		struct DNS_RR *addFileRR;
		addFileRR = malloc(sizeof(DNS_ResouceRecord));
		addFileRR->name=malloc(MAX_SIZE_OF_DOMAIN);
		addFileRR->rdata=malloc(MAX_SIZE_OF_DOMAIN);
		while(fscanf(RR,"%s ",addFileRR->name)!=EOF)
		{
			fscanf(RR,"%d ",&addFileRR->ttl);
			char type[10],_class[10];
			fscanf(RR,"%s ",_class);
			fscanf(RR,"%s ",type);
			addFileRR->type = strTypeToCode(type);
			fscanf(RR,"%s\n",addFileRR->rdata);
			if(strcmp(fileRR->rdata,addFileRR->name)==0)
			{
				printf("邮件服务器：\n");
				//生成addition RR
				create_resource_record(addFileRR,fileRR->rdata, 1, 1, fileRR->ttl, 0, addFileRR->rdata);
				encode_resource_record(addFileRR,buffer,bufferPointer);
				print_resource_record(addFileRR);
				break;
			}
		}	
	}
	fclose(RR);
	return over;
}

void loopFindNS(struct DNS_Query *query_section,char *RRDOCUMENT,char *buffer,int *bufferPointer)
{
	FILE *RR = fopen( RRDOCUMENT, "r" );
	cut(&query_section->name);
	//剪掉首段地址，进行第二次搜索
	while(query_section->name!=NULL)
	{
		fseek(RR,0,0);  
		
		struct DNS_RR *nextRR;
		nextRR = malloc(sizeof(DNS_ResouceRecord));
		nextRR->name=malloc(MAX_SIZE_OF_DOMAIN);
		nextRR->rdata=malloc(MAX_SIZE_OF_DOMAIN);
		while(fscanf(RR,"%s ",nextRR->name)!=EOF)
		{
			fscanf(RR,"%d ",&nextRR->ttl);
			char type[10],_class[10];
			fscanf(RR,"%s ",_class);
			fscanf(RR,"%s ",type);
			nextRR->type = strTypeToCode(type);
			fscanf(RR,"%s\n",nextRR->rdata);
			if(strcmp(query_section->name,nextRR->name)==0)
			{
				printf("\n下一级服务器信息：\n");
				//生成头
				struct DNS_Header *header;
				header = malloc(sizeof(DNS_HEAD));
				unsigned short tag = create_tag(1,0,1,0,0,0,0,0);
				create_query_header(header,999,tag,0,0,1,1);
				encode_header(header,buffer,bufferPointer);
				print_header(header);
				
				//生成authority RR  NS记录type=2   此时query_section->name经过cut后已经变成了下一个要去的DNS服务器域名
				struct DNS_RR *authRR;
				authRR = malloc(sizeof(DNS_ResouceRecord));
				create_resource_record(authRR, query_section->name, 2, 1, nextRR->ttl, 0, query_section->name);
				encode_resource_record(authRR,buffer,bufferPointer);
				print_resource_record(authRR);
				
				//生成additon RR   A记录type=1
				struct DNS_RR *addRR;
				addRR = malloc(sizeof(DNS_ResouceRecord));
				create_resource_record(addRR, query_section->name, 1, 1, nextRR->ttl, 0, nextRR->rdata);
				encode_resource_record(addRR,buffer,bufferPointer);
				print_resource_record(addRR);
				
				goto out;
			}
		}	
		cut(&query_section->name);	
	}
	out:
	fclose(RR);
}






