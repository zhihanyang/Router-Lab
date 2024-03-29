#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  //printf("disassemble\n");
  int base_offset = 27;//0x2d;
  int command  = packet[++base_offset];
  //printf("len:%d command:%d\n",len, command);
  // for(int i=base_offset;i<len;++i){
  //   printf("%d ",packet[i]);
  // }
  if(command !=1 && command !=2){
    return false;
  }
  int version = packet[++base_offset];
  if(version != 2){
    return false;
  }
  // printf("version:%d",version);
  (*output).numEntries=0;
  if(packet[++base_offset]!=0 ||packet[++base_offset]!=0){
    return false;
  }
  for(int entry_index=0;base_offset<len-1;entry_index++){
    //printf("entry:%d baseoffset:%d\n",entry_index, base_offset);
    int family = packet[++base_offset]<<8;
    family+=packet[++base_offset];
    //printf("famlity:%d\n",family);
    if(command==2&&family!=2 || command==1 &&family!=0){
      //printf("command:%d\n",command);
      return false;
    }
    int tag = packet[++base_offset]<<8;
    tag+=packet[++base_offset];
    if(tag!=0){
      return false;
    }
    RipEntry& nowEntry = ((*output).entries[entry_index]);
    nowEntry.addr = packet[++base_offset];
    nowEntry.addr+= packet[++base_offset]<<8;
    nowEntry.addr+= packet[++base_offset]<<16;
    nowEntry.addr+= packet[++base_offset]<<24;

    nowEntry.mask = packet[++base_offset];
    nowEntry.mask+= packet[++base_offset]<<8;
    nowEntry.mask+= packet[++base_offset]<<16;
    nowEntry.mask+= packet[++base_offset]<<24;
    //bool serial = true;
    bool reverse = false;
    //if(nowEntry.mask&1==0)return false;
    for(int i=0;i<31;++i){
      if((nowEntry.mask>>i&1) == (nowEntry.mask>>(i+1)&1))continue;
      //printf("i=%d, %d\n",i,nowEntry.mask>>i&1);
      if(reverse){
        //printf("i=%d, %d\n",i,nowEntry.mask>>i&1);
        return false;
      }
      reverse=true;
    }

    nowEntry.nexthop = packet[++base_offset];
    nowEntry.nexthop+= packet[++base_offset]<<8;
    nowEntry.nexthop+= packet[++base_offset]<<16;
    nowEntry.nexthop+= packet[++base_offset]<<24;
    //printf("hop:%d\n",nowEntry.metric);

    nowEntry.metric = packet[++base_offset];
    nowEntry.metric+= packet[++base_offset]<<8;
    nowEntry.metric+= packet[++base_offset]<<16;
    nowEntry.metric+= packet[++base_offset]<<24;
    int metric = ntohl(nowEntry.metric);
    //printf("metric:%d",metric);
    if(metric<1||metric>16)return false;
    //printf("mash:%d\n",nowEntry.metric);

    (*output).numEntries++;
    //printf("num:%d\n",(*output).numEntries);
  }
  (*output).command = command;
  //printf("len:%d offset:%d",len,base_offset);
  if(base_offset > len)
    return false;
  //printf("done\n");
  return true;
  // for(int i=0;i<len;++i){
  //   printf("%c",packet[i]);
  // }
  return false;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  int base_offset = 0;
  buffer[base_offset++]=(*rip).command;
  buffer[base_offset++]=0x2;
  buffer[base_offset++]=0;
  buffer[base_offset++]=0;
  for(int i=0 ;i<(*rip).numEntries;++i){
    buffer[base_offset++]=0;
    buffer[base_offset++]=(*rip).command==2 ? 2:0;
    buffer[base_offset++]=0;
    buffer[base_offset++]=0;

    const RipEntry& nowEntry = ((*rip).entries[i]);
    buffer[base_offset++]=nowEntry.addr;
    buffer[base_offset++]=nowEntry.addr>>8;
    buffer[base_offset++]=nowEntry.addr>>16;
    buffer[base_offset++]=nowEntry.addr>>24;

    buffer[base_offset++]=nowEntry.mask;
    buffer[base_offset++]=nowEntry.mask>>8;
    buffer[base_offset++]=nowEntry.mask>>16;
    buffer[base_offset++]=nowEntry.mask>>24;

    buffer[base_offset++]=nowEntry.nexthop;
    buffer[base_offset++]=nowEntry.nexthop>>8;
    buffer[base_offset++]=nowEntry.nexthop>>16;
    buffer[base_offset++]=nowEntry.nexthop>>24;

    buffer[base_offset++]=nowEntry.metric;
    buffer[base_offset++]=nowEntry.metric>>8;
    buffer[base_offset++]=nowEntry.metric>>16;
    buffer[base_offset++]=nowEntry.metric>>24;
  }
  return base_offset;
}
