/****************************************************************************

Copyright(c) 2016 - 2017 by IoTelic Technologies. ALL RIGHTS RESERVED.

This Information is proprietary to IoTelic Technologies and MAY NOT
be copied by any method or incorporated into another program without
the express written consent of Iotelic. This Information or any portion
thereof remains the property of Iotelic. The Information contained herein
is believed to be accurate and Iotelic assumes no responsibility or
liability for its use in any way and conveys no license or title under
any patent or copyright and makes no representation or warranty that this
Information is free from patent or copyright infringement.

****************************************************************************/

#ifndef IOT_PLC_API_H
#define IOT_PLC_API_H

#include <stdint.h>
#include "iot_pkt_api.h"

/* application id range definition */
#define IOT_PLC_APP_ID_MIN              48
#define IOT_PLC_APP_ID_MAX              254

#define IOT_PLC_LOCAL_RETRY_CNT         0

/** \defgroup PLCLIB_APIs PLCLIB APIs
  * @brief WQ30x1 PLCLIB APIs
  */


/** @addtogroup PLCLIB_APIs
  * @{
  */

/** \defgroup PLC_SHARE_APIs PLC SHARE APIs
  * @brief Share APIs
  *
  * APIs can be called by CCO or STA devices
  */

/** @addtogroup PLC_SHARE_APIs
  * @{
  */

/**
 * @brief (*iot_plc_recv_func_t)() - callback to receive event from plc.
 * @param:      parameter registered in iot_plc_register_app
 * @param:      buffer to store the event detail, application should call
 *              iot_free_pkt functio ASAP to free the iot pkt. it's very scarce
 *              resource.
 */
typedef void (*iot_plc_recv_func_t)(void *param, iot_pkt_t *pkt);

typedef struct _iot_plc_app {
    /* application id */
    uint8_t             app_id;
    /* default priority */
    uint8_t             prio;
    /* callback to receive event from plc */
    iot_plc_recv_func_t recv;
    /* parameter that will be transferred back alone with the callback */
    void                *param;
} iot_plc_app_t;

/* plc application hanlder */
typedef void *iot_plc_app_h;

/**
 * @brief iot_plc_register_app() - register plc application. the result will
 *                      be notified through iot_plc_recv_func_t callback.
 * @param app:          pointer to application descripter
 *
 * @return              NULL -- for failure case
 * @return              otherwise -- plc application handler
 */
iot_plc_app_h iot_plc_register_app(iot_plc_app_t *app);

/**
 * @brief iot_plc_alloc_msdu() - allocate iot packet for msdu data send.
 *                      be notified through iot_plc_recv_func_t callback.
 * @param handle:       plc application handler
 * @param msg_type:     type of the message. see IOT_PLC_MSG_TYPE_XXX
 * @param ack_type:     required ack type. see IOT_PLC_ACK_TYPE_XXX
 * @param dst:          final destination mac address
 * @param src:          original source mac address
 * @param lid:          link identifier.
 *                          0 - 3   priority,
 *                          4 - 254 business category,
 *                          255     invalid. if set to 255, default
 *                          priority registered will be used.
 * @param len:          message length
 * @param retry_cnt:    retry times of sending if remote not acked.
 * @return              the pointer of iot packet
 */
iot_pkt_t *iot_plc_alloc_msdu(iot_plc_app_h handle, uint8_t msg_type,
    uint8_t ack_type, uint8_t *dst, uint8_t *src, uint8_t lid, uint16_t len,
    uint8_t retry_cnt);

/**
 * @brief iot_plc_send_msdu() - send a packet through the plc. there is no
 *                      guarantee that the packet will be delivered to the
 *                      final destination as the plc network is unreliable. the
 *                      pkt must be allocated through iot_plc_alloc_msdu api.
 * @param handle:       plc application handler
 * @param pkt:          pointer to the packet
 */
void iot_plc_send_msdu(iot_plc_app_h handle, iot_pkt_t *pkt);

/**
 * @brief iot_plc_query_dev_info() - get info of local device
 * @param handle:       plc application handler
 */
void iot_plc_query_dev_info(iot_plc_app_h handle);

/**
 * @brief iot_plc_query_nid() - get nid of the current network, a
 *                      iot_plc_dev_info_rpt message will be replied
 * @param handle:       plc application handler
 */
void iot_plc_query_nid(iot_plc_app_h handle);

/**
 * @brief iot_plc_query_dev_info() - get info of neighbour network
 *                          a iot_plc_nb_nw_info_t message will be replied
 * @param handle:           plc application handler
 */
void iot_plc_query_nb_nw_info(iot_plc_app_h handle);

/**
 * @brief iot_plc_set_cfg() - set configuration of local device
 * @param handle:       plc application handler
 * @param addr:         mac address to be set. set NULL if mac address
 *                      change not required.
 * @param dev_type:     device type to be set. set IOT_PLC_DEV_TYPE_INVALID
 *                      if device type chage not required.
 * @param reset:        reset lower layer to apply the cfg immediately.
 */
void iot_plc_set_cfg(iot_plc_app_h handle, uint8_t *addr, uint8_t dev_type,
    uint8_t reset);

/**
 * @brief iot_plc_get_cfg() - get configuration of local device
 * @param handle:       plc application handler
 * @param addr:         mac address to be get.
 * @param dev_type:     device type to be set. set IOT_PLC_DEV_TYPE_INVALID
 *                      if device type change is not required.
 */
void iot_plc_get_cfg(iot_plc_app_h handle, uint8_t addr[6], uint8_t dev_type);

/**
 * @brief iot_plc_start_nw_fmt() - start network formation
 * @param handle:       plc application handler
 * @param force:        flag to mark if force start required. if plc network
 *                      formation already started, set this flag will restart
 *                      the whole process from the very beginning.
 */
void iot_plc_start_nw_fmt(iot_plc_app_h handle, uint8_t force);

/**
 * @brief iot_plc_query_band_info() - query carrier communication frequency band
 *
 * @param  handle:     plc application handler
 */
void iot_plc_query_band_info(iot_plc_app_h handle);

/**
 * @brief   query the founded neighbor devices in the same network. the result
 *          will be notified through iot_plc_recv_func_t callback.
 * @param handle:           plc application handler
 * @param start:            start tei of the query
 * @param cnt:              requested number of valid entries
 */
void iot_plc_query_neighbor_dev(iot_plc_app_h handle, uint16_t start,
    uint16_t cnt);

/**
 * @brief   iot_plc_query_tei_addr_info() - query tei address information
 * @param   handle:     plc application handler
 * @param   start_tei:  start tei
 * @param   offset:     start query position. bit0 = 0, bit1 = 1, bit2 = 2, ...
 * @param   bm_len:     bm len
 * @param   bm:         tei bitmap used for query tei addr,
 *                      bit0 represent start tei,
 *                      bit1 represent start tei + 1 and so on
 */
void iot_plc_query_tei_addr_info(iot_plc_app_h handle,
    uint16_t start_tei, uint16_t offset, uint8_t bm_len, uint8_t *bm);

/**
 * @brief   set carrier communication tx power cap
 *
 * @param   handle: plc application handler
 * @param   power:  tx power cap. unit is 1 dbm.
 */
void iot_plc_set_tx_power_cap(iot_plc_app_h handle, uint8_t power);

/**
  * @}
  */

/**
  * @}
  */

#endif /* IOT_PLC_API_H */