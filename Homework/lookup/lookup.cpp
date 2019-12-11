#include "../boilerplate/router.h"
#include "../boilerplate/rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <vector>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
std::vector<RoutingTableEntry> routingTable;

void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  if(insert){
    for(auto iter = routingTable.cbegin(); iter != routingTable.cend(); iter++){
      if((*iter).addr == entry.addr && (*iter).len == entry.len){
        routingTable.erase(iter);
      }
    }
    routingTable.insert(routingTable.end(),entry);
    //printf("len:%d",entry.len);
  }else{
    for(auto iter = routingTable.cbegin(); iter != routingTable.cend(); iter++){
      if((*iter).addr == entry.addr && (*iter).len == entry.len){
        routingTable.erase(iter);
        return;
      }
    }
  }
}

void update(RoutingTableEntry entry) {
  // TODO:
    for(auto iter = routingTable.cbegin(); iter != routingTable.cend(); iter++){
      if((*iter).addr == entry.addr && (*iter).len == entry.len){
        if(entry.if_index == (*iter).if_index || entry.metric +1 <= (*iter).metric){
          routingTable.erase(iter);
          routingTable.insert(routingTable.end(),entry);
        } 
        return;
      }
    }
    // if(route_change)
    routingTable.insert(routingTable.end(),entry);
    //printf("len:%d",entry.len);

}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  int maxlen = 0;
  //printf("%d",routingTable.size());
  for(auto iter = routingTable.cbegin(); iter != routingTable.cend(); iter++){
      uint32_t res = (*iter).addr ^ addr;
      uint32_t mask = (*iter).len < 32 ? (1<<(*iter).len)-1 : -1;
      //printf("res:%d mask:%d &:%d\n",res,mask,res&mask);
      uint32_t token = res&mask;

      if(token==0 && (*iter).len>maxlen){
        maxlen = (*iter).len;
        *nexthop = (*iter).nexthop;
        *if_index = (*iter).if_index;
      }
    }
  if(maxlen>0)
    return true;
  *nexthop = 0;
  *if_index = 0;
  return false;
}
