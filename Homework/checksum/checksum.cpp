#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
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
  return sum == checksum;
}
