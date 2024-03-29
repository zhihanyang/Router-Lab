#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  // TODO:
  int mlen = (packet[0]&15)<<2;
  int sum = (packet[10]<<8)+packet[11];
  packet[10]=packet[11]=0;
  int checksum = 0;
  for(int i=0;i<mlen;++i){
    int now = (packet[i]<<8)+packet[i+1];
    ++i;
    checksum+=now;
    int mask=65535;
    while(checksum>mask){
      checksum = (checksum&mask)+(checksum>>16);
    }
  }
  checksum^=65535;
  //printf("check:");
  if(checksum != sum)
    return false;
  //printf("true\n");
  packet[8]=packet[8]-1;
  checksum = 0;
  for(int i=0;i<mlen;++i){
    int now = (packet[i]<<8)+packet[i+1];
    ++i;
    checksum+=now;
    int mask=65535;
    while(checksum>mask){
      checksum = (checksum&mask)+(checksum>>16);
    }
  }
  checksum^=65535;
  packet[11]=checksum&255;
  packet[10]=checksum>>8;
  return true;
}
