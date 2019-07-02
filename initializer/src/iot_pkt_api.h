/****************************************************************************

Copyright(c) 2016 by IoTelic Technologies. ALL RIGHTS RESERVED.

This Information is proprietary to IoTelic Technologies and MAY NOT
be copied by any method or incorporated into another program without
the express written consent of Iotelic. This Information or any portion
thereof remains the property of Iotelic. The Information contained herein
is believed to be accurate and Iotelic assumes no responsibility or
liability for its use in any way and conveys no license or title under
any patent or copyright and makes no representation or warranty that this
Information is free from patent or copyright infringement.

****************************************************************************/

#ifndef IOT_PKT_API_H
#define IOT_PKT_API_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/** \defgroup PACKET_APIs PACKET APIs
  * @brief WQ30x1 PACKET API
  *
  * IOT packet helper functions.
  * PKT are shared pools along whole system.
  * SDK user should pay attention on pkt ownership to free.
  * Please reference to each API descrption for detail
  *
  */

/** @addtogroup PACKET_APIs
  * @{
  */


#define IOT_PKT_BLOCK_ALL  0
#define IOT_PKT_BLOCK_HEAD 1
#define IOT_PKT_BLOCK_DATA 2
#define IOT_PKT_BLOCK_TAIL 3
#define IOT_PKT_BLOCK_END 4


/* define maximum supported packet pool config */
#define IOT_PKT_POOL_MAX   8


typedef struct _iot_pkt {
    uint8_t     *head;
    uint8_t     *data;
    uint8_t     *tail;
    uint8_t     *end;
#if IOT_PKT_DEBUG
    /*the file name who alloc this pkt*/
    const char  *file_name;
    /*the line number in the file*/
    uint32_t    line_num;
#endif
} iot_pkt_t;

typedef struct _iot_pkt_list {
    struct _iot_pkt_list * next;
    iot_pkt_t *pkt;
} iot_pkt_ls;

/**
 * @brief iot_pkt_mem_alloc() - allocate a packet for sending/receiving data.
 * the packet can be regards as 3 virtual blocks: head, data, tail.
 *       ---------- <-- head_ptr (fixed)
 *       |  head  |
 *       |--------| <-- data_ptr
 *       |  data  |
 *       |        |
 *       |--------| <-- tail_ptr
 *       |  tail  |
 *       ---------- <-- end_ptr (fixed)
 * With this implementation, upper layer can reserve some space for
 * lower layer to append header and checksum.
 * A new allocated iot_pkt only has tail block. Size of head/data block is 0.
 * Please use corresponding APIs to adjust size of each block.
 *
 * @param size:         size of the packet user want to be allocate.
 * @param module_id:    id of the module to allocate the packet
 * @param init_mem:     set to 0 if memory initialization for the packet data
 *                      is not required to improve efficiency.
 * @param file_name:    the file name who alloc this pkt
 * @param line_num:     the line number in the file
 *
 * @return          NULL -- No memory available.
 * @return          otherwise -- address of the new allocated packet
 */
#if IOT_PKT_DEBUG
iot_pkt_t* iot_pkt_mem_alloc(uint32_t size, uint8_t module_id,
    uint8_t init_mem, const char* file_name, uint32_t line_num);
#else
iot_pkt_t* iot_pkt_mem_alloc(uint32_t size, uint8_t module_id,
    uint8_t init_mem);
#endif

/**
 * @brief iot_pkt_dataptr_addr() - get the address of data pointer of a iot_pkt.
 * @param buf:     the iot_pkt to operate on.
 *
 * @return         the address of the pointer to data block in the iot packet.
 */
uint8_t** iot_pkt_dataptr_addr(iot_pkt_t* buf);

/**
 * @brief iot_pkt_reserve() - reserve a head block in iot_pkt.
 * @param buf:     the iot pkt to operate on.
 * @param size:    size of the head block.
 *
 * @return         NULL -- if there is not enough memory for this operation
 * @return         otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_reserve(iot_pkt_t* buf, uint32_t size);

/**
 * @brief iot_pkt_put() - extend data block in the end. tail block will shrink
 *                        accordingly
 * @param buf:     the iot pkt to operate on.
 * @param size:    size in byte to extend in the end of data block.
 *
 * @return         NULL -- if there is not enough memory for this operation
 * @return         otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_put(iot_pkt_t* buf, uint32_t size);

/**
 * @brief iot_pkt_shrink() - shrink data block in the end. tail block will
 *                           extend accordingly
 * @param buf:     the iot pkt to operate on.
 * @param size:    size in byte to extend in the end of data block.
 *
 * @return         NULL -- if there is not enough memory for this operation
 * @return         otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_shrink(iot_pkt_t* buf, uint32_t size);

/**
 * @brief iot_pkt_push() - extend data block in front,
 *                         head block will shrink accordingly.
 * @param buf:     the iot pkt to operate on.
 * @param size:    size in byte to extend in the end of data block.
 *
 * @return         NULL -- if there is not enough memory for this operation
 * @return         otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_push(iot_pkt_t* buf, uint32_t size);

/**
 * @brief iot_pkt_pull() - extend data block in front,
 *                         head block will extend accordingly.
 * @param buf:     the iot pkt to operate on.
 * @param size:    size in byte to extend in the end of data block.
 *
 * @return        NULL -- if there is not enough memory for this operation
 * @return        otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_pull(iot_pkt_t* buf, uint32_t size);

/**
 * @brief iot_pkt_set_data() - manually set the start position of data block.
 * @param buf:     the iot pkt to operate on.
 * @param new_data:new start position of data block.
 *
 * @return         NULL -- if new_data does't point to pos in head block
 *                         or data block
 * @return         otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_set_data(iot_pkt_t* buf, void* new_data);

/**
 * @brief iot_pkt_set_tail() - manually set the start position of data block.
 *                             new_tail shall point to a valid position in
 *                             current data block or tail block.
 * @param buf:     the iot pkt to operate on.
 * @param new_tail:new start position of tail block.
 *
 * @return         NULL -- if new_data does't point to pos in data block
 *                         or tail block
 * @return         otherwise -- pointer to data block in the iot packet.
 */
uint8_t* iot_pkt_set_tail(iot_pkt_t* buf, void* new_tail);

/**
 * @brief iot_pkt_free() - free a packet allocated by iot_pkt_alloc.
 * @param buf:     address of the packet to be freed.
 */

void iot_pkt_free(iot_pkt_t* buf);

/**
 * @brief iot_pkt_block_ptr() - get address of a specific block in an iot packet.
 * @param buf:          the iot_pkt to operate on.
 * @param block_type:   Specify the type of the block
 *                      should be one of the following values:
 *                          - IOT_PKT_BLOCK_HEAD
 *                          - IOT_PKT_BLOCK_DATA
 *                          - IOT_PKT_BLOCK_TAIL
 *
 * @return              NULL -- arguments are invalid.
 * @return              otherwise -- address of the specific block in the iot packet.
 */
uint8_t* iot_pkt_block_ptr(iot_pkt_t* buf, uint8_t block_type);

/**
 * @brief iot_pkt_block_len() - get length of a specific block.
 * @param buf:          the iot pkt to operate on.
 * @param block_type:   the type of the block
 *                      should be one of the following value:
 *                          - IOT_PKT_BLOCK_ALL
 *                          - IOT_PKT_BLOCK_HEAD
 *                          - IOT_PKT_BLOCK_DATA
 *                          - IOT_PKT_BLOCK_TAIL
 *
 * @return              NULL -- arguments are invalid.
 * @return              otherwise -- size of the specific block in the iot packet.
 */
uint32_t iot_pkt_block_len(iot_pkt_t* buf, uint8_t block_type);

/**
 * @brief iot_pkt_reset() - reset a packet allocated by iot_pkt_alloc
 * @param buf:          address of the packet to be reset
 */
static inline void iot_pkt_reset(iot_pkt_t *buf)
{
    memset(buf->head, 0, (buf->end - buf->head));
    buf->data = buf->tail = buf->head;
}

/**
 * @brief iot_pkt_cpy() - copy the packet from src to dst
 * @param dst:          address of the destination packet
 * @param src:          address of the source packet
 */
static inline void iot_pkt_cpy(iot_pkt_t *dst, iot_pkt_t *src)
{
    if ((dst->end - dst->head) < (src->tail - src->head)) {
        assert(0);
    } else {
        dst->data = dst->head + (src->data - src->head);
        dst->tail = dst->data + (src->tail - src->data);
        memcpy(dst->data, src->data, (src->tail - src->data));
    }
}

/**
 * @brief iot_pkt_get() - to make the alloc and resv together
 * @param buf_size:         at least buf_size iot_pkt
 * @param resv_head_size:   resv_head_size
 *
 * @return              iot pkt pointer if successful,other for failed
 */
void* iot_pkt_get(uint32_t buf_size, uint32_t resv_head_size, uint8_t module_id);



/**
 * @brief void iot_pkt_pktpool_status() - return pkt pool status,eg free pkt num
 * @param pool_idx:     IN  pkt pool index 0~(IOT_PKT_POOL_MAX-1)
 * @param bufsz:        OUT pkt data size
 * @param freenum:      OUT free pkt num
 * @param totalnum:     OUT toal pkt num
 * @return              0 -- success, otherwise -- fail
 */

uint32_t iot_pkt_pktpool_status(uint8_t pool_idx, uint32_t* bufsz,
    uint32_t* freenum, uint32_t* totalnum);

/**
 * get data ptr
 */
#define iot_pkt_data(pkt) iot_pkt_block_ptr(pkt, IOT_PKT_BLOCK_DATA)
#define iot_pkt_data_len(pkt) \
    iot_pkt_block_len(pkt, IOT_PKT_BLOCK_DATA)

uint32_t iot_pkt_list_block_data_len(iot_pkt_ls *pkt_list);
uint32_t iot_pkt_list_item_count(iot_pkt_ls *pkt_list);
void iot_pkt_list_free_every_pkt_mem(iot_pkt_ls *pkt_list);

#define iot_pkt_list_data_len(pkt_lst) \
    iot_pkt_list_block_data_len(pkt_lst)

#define iot_pkt_list_item_cnt(pkt_lst) \
    iot_pkt_list_item_count(pkt_lst)

#define iot_pkt_list_free_pkts(pkt_lst) \
    iot_pkt_list_free_every_pkt_mem(pkt_lst)

/**
 * get tail ptr
 */
#define iot_pkt_tail(pkt) iot_pkt_block_ptr(pkt, IOT_PKT_BLOCK_TAIL)
#define iot_pkt_tail_len(pkt) \
    iot_pkt_block_len(pkt, IOT_PKT_BLOCK_TAIL)

#if IOT_PKT_DEBUG
#define iot_pkt_alloc(size, module_id) iot_pkt_mem_alloc(size, module_id, 1, \
    __FUNCTION__, __LINE__)
#else
#define iot_pkt_alloc(size, module_id) iot_pkt_mem_alloc(size, module_id, 1)
#endif

#if IOT_PKT_DEBUG
#define iot_pkt_alloc_ext(size, module_id, init_mem) iot_pkt_mem_alloc(size, \
    module_id, init_mem, __FUNCTION__, __LINE__)
#else
#define iot_pkt_alloc_ext(size, module_id, init_mem) iot_pkt_mem_alloc(size, \
    module_id, init_mem)
#endif

/**
 * @brief iot_pkt_validation() - to make the validation pkt legal
 * @param pkt:                   judge pkt legal
 *
 * @return                       VS_HSM_ERR_OK: legal  ,  VS_HSM_ERR_INVAL: illegal
 */
uint32_t iot_pkt_validation(iot_pkt_t *pkt);

#endif /* IOT_PKT_API_H */
