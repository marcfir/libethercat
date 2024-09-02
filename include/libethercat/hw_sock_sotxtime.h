/**
 * \file hw_sock_sotxtime.c
 *
 * \author Marc Fischer <marcifr@proton.me>
 *
 * \date 02 September 2024
 *
 * \brief SOCK_SO_TXTIME hardware access functions
 *
 */

/*
 * This file is part of libethercat.
 *
 * libethercat is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * 
 * libethercat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public 
 * License along with libethercat (LICENSE.LGPL-V3); if not, write 
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth 
 * Floor, Boston, MA  02110-1301, USA.
 * 
 * Please note that the use of the EtherCAT technology, the EtherCAT 
 * brand name and the EtherCAT logo is only permitted if the property 
 * rights of Beckhoff Automation GmbH are observed. For further 
 * information please contact Beckhoff Automation GmbH & Co. KG, 
 * Hülshorstweg 20, D-33415 Verl, Germany (www.beckhoff.com) or the 
 * EtherCAT Technology Group, Ostendstraße 196, D-90482 Nuremberg, 
 * Germany (ETG, www.ethercat.org).
 *
 */

#ifndef LIBETHERCAT_HW_SOCK_SOTXTIME_H
#define LIBETHERCAT_HW_SOCK_SOTXTIME_H

#include <libethercat/hw.h>
#include <libethercat/ec.h>
#include <libosal/task.h>

typedef struct hw_sock_sotxtime {
    struct hw_common common;

    int sockfd;                 //!< raw socket file descriptor non-real-time traffic
    int sockfd_high;                //!< raw socket file descriptor for real-time traffic with so_txtime
    osal_uint64_t next_txtime;      //!< 
    int ifindex;                    //!< 
    int if_speed; //!< current link speed in mbit
    
    osal_uint8_t send_frame[ETH_FRAME_LEN]; //!< \brief Static send frame.
    osal_uint8_t recv_frame[ETH_FRAME_LEN]; //!< \brief Static receive frame.

    // receiver thread settings
    osal_task_t rxthread;           //!< receiver thread handle
    int rxthreadrunning;            //!< receiver thread running flag
} hw_sock_sotxtime_t;

//! Opens EtherCAT hw device.
/*!
 * \param[in]   phw             Pointer to hw handle. 
 * \param[in]   pec             Pointer to master structure.
 * \param[in]   devname         Null-terminated string to EtherCAT hw device name.
 * \param[in]   prio            Priority for receiver thread.
 * \param[in]   cpu_mask        CPU mask for receiver thread.
 * \param[in]   socket_priority Socket priority.
 *
 * \return 0 or negative error code
 */
int hw_device_sock_sotxtime_open(struct hw_sock_sotxtime *phw, struct ec *pec, const osal_char_t *devname, int prio, int cpu_mask, int socket_prio, int clock_id);

//! set txtime time stamp for the tx high queue. The timestamp must be calculated
//! in the user application in connection with the application scheduling
/*!
 * \param phw hardware handle
 * \param next_txtime next txtime
 * \return 0 or error code
 */
int hw_high_set_next_txtime(struct hw_sock_sotxtime *phw, osal_int64_t next_txtime);

#endif // LIBETHERCAT_HW_SOCK_SOTXTIME_H

