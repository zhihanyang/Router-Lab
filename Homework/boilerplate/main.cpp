#include "../../HAL/include/router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <vector>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern void update(RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern std::vector <RoutingTableEntry> routingTable;

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};

RipPacket response(uint32_t if_index){
  RipPacket res;
  res.command = 0x2;
  int entry_num = 0;
  for (uint32_t i=0; i<routingTable.size(); ++i){
    if(routingTable[i].if_index == if_index)
      continue;
    uint32_t mask = (1<<routingTable[i].len)-1;
    mask <<= 32 - routingTable[i].len;
    uint32_t entrymask = 0;//转换端序
    for(int i=0 ; i<32 ; i+=8){
      entrymask += (mask >> i) & 0xff << (24 - i);
    }
    RipEntry entry = {
      .addr = routingTable[i].addr,
      .mask = entrymask,
      .nexthop = routingTable[i].nexthop,
      .metric = routingTable[i].metric
    };
    res.entries[entry_num++] = entry;
  }
  res.numEntries = entry_num;
}

int format_packet(in_addr_t src_addr, in_addr_t dst_addr, RipPacket *resp, uint8_t* buffer){
  // RIP
  uint32_t rip_len = assemble(resp, &buffer[20 + 8]);

  buffer[0] = 0x45;
  buffer[1] = 0xc0;

  // length calculation for ip and udp
  // ip total length calculate
  uint32_t ip_total_len = rip_len + 28;
  buffer[2] = (ip_total_len & 0xff00) >> 8;
  buffer[3] = ip_total_len & 0xff;

  // IP Id, flags, TTL and protocol
  for(int offset = 4;offset < 8; offset++)
    buffer[offset] = 0x00;
  buffer[8] = 0x01;//ttl = 1
  buffer[9] = 0x11;//protocol = 17
  // IP Header Checksum(placeholder)
  buffer[10] = 0x00;
  buffer[11] = 0x00;
  // IP Source Addr
  for(int offset = 0;offset < 4;offset ++)
    buffer[offset+12] = src_addr >> (offset * 8) & 0xff;
  // IP Dest Addr = 224.0.0.9
  for(int offset = 0;offset < 4;offset ++)
    buffer[offset+16] = dst_addr >> (offset * 8) & 0xff;
  
  // checksum calculation for ip and udp
  // ip header checksum calculation
  uint32_t checksum = 0x0000;
  for(int i=0 ; i<20 ; ++i){
    int now = (buffer[i]<<8)+buffer[i+1];
    ++i;
    checksum+=now;
    int mask=65535;
    while(checksum>mask){
      checksum = (checksum&mask)+(checksum>>16);
    }
  }
  checksum^=65535;
  buffer[11]=checksum&255;
  buffer[10]=checksum>>8;

  // UDP
  // port = 520
  buffer[20] = 0x02;
  buffer[21] = 0x08;
  buffer[22] = 0x02;
  buffer[23] = 0x08;

  // udp length calculate
  uint32_t udp_len = rip_len + 8;
  buffer[24] = (udp_len & 0xff00) >> 8;
  buffer[25] = udp_len & 0xff;
  
  // if you don't want to calculate udp checksum, set it to zero
  // udp checksum calculating, maybe not using it now
  buffer[26] = 0x00;
  buffer[27] = 0x00;//??
  return rip_len;
}
in_addr_t multicast_addr = {0x090000e0}; //组播地址

int main(int argc, char *argv[]) {
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i] & 0x00FFFFFF, // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 1 //[1,15]
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do?
      for(int i=0; i<N_IFACE_ON_BOARD;++i){
        RipPacket resp = response(i);
        int rip_len = format_packet(i, multicast_addr, &resp, output);
        macaddr_t dest_mac;
        HAL_ArpGetMacAddress(i, multicast_addr, dest_mac);
        HAL_SendIPPacket(i, output, rip_len + 20 + 8, dest_mac);
      }
      printf("Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // pagcket is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr=0, dst_addr=0;
    // extract src_addr and dst_addr from packet
    // big endian
    for(int offset = 0;offset < 4;offset ++){
      src_addr += packet[offset+12] << (offset * 8);
      dst_addr += packet[offset+16] << (offset * 8);
    }
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?
    dst_is_me = dst_is_me || memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0 ;
    
    if (dst_is_me) {
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // request
          //if entry == 1 ?

          //3a.3 request
          RipPacket resp = response(if_index);
          // ...
          // RIP
          int rip_len = format_packet(addrs[if_index], multicast_addr, &resp, output);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          //3a.2
          // response
          // TODO: use query and update
          for(int i=0; i<rip.numEntries ; ++i){
            RipEntry entry = {
              .addr = rip.entries[i].addr,
              .mask = rip.entries[i].mask,
              .nexthop = rip.entries[i].nexthop,
              .metric = rip.entries[i].metric
            };
            uint32_t entrymask = 0;//转换端序
            for(int i=0 ; i<32 ; i+=8){
              entrymask += (entry.mask >> i) & 0xff << (24 - i);
            }
            uint32_t len = 32;// calculate the len
            while(entrymask & 1 != 1){
              entrymask >>=1;
              len--;
            }
            RoutingTableEntry routingTableEntry = {
              .addr = entry.addr,
              .len = len,
              .if_index = if_index,
              .nexthop = entry.nexthop,
              .metric = entry.metric
            };
            if(rip.entries[i].metric + 1 > 16){
              // invalid metric, deleting it in routing table and sending it back later
              // maybe not using it now
              // invalid.entries[invalidNum ++] = entry;
              update(false, routingTableEntry);
            }else{
              // update routing table
              // new metric = ?
              // update metric, if_index, nexthop
              // what is missing from RoutingTableEntry?(the int "metric")
              // TODO: use query and update
              // triggered updates? ref. RFC2453 3.10.1
              update(routingTableEntry);
            }
          }
        }
      } else {
        //disassemble error;
        printf("disassemble error.\n");
      }
    } else {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (query(dst_addr, &nexthop, &dest_if)) {//src or dst?
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            if(output[8] == 0)
              continue;
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
          }
        } else {
          // not found
        }
      
    }
  }
  return 0;
}