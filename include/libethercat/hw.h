/**
 * \file hw.h
 *
 * \author Robert Burger <robert.burger@dlr.de>
 *
 * \date 24 Nov 2016
 *
 * \brief hardware access functions
 *
 */


/*
 * This file is part of libethercat.
 *
 * libethercat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libethercat is distributed in the hope that 
 * it will be useful, but WITHOUT ANY WARRANTY; without even the implied 
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libethercat
 * If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBETHERCAT_HW_H
#define LIBETHERCAT_HW_H

#include <libosal/task.h>
#include <libosal/types.h>
#include <libosal/mutex.h>

#include "libethercat/pool.h"

//! hardware structure
typedef struct hw {
    int sockfd;                     //!< raw socket file descriptor
    osal_uint32_t mtu_size;              //!< mtu size

    // receiver thread settings
    osal_task_t rxthread;           //!< receiver thread handle
    int rxthreadrunning;            //!< receiver thread running flag
    int rxthreadprio;               //!< receiver thread priority
    osal_uint32_t rxthreadcpumask;       //!< recevied thread cpu mask

    int mmap_packets;
    osal_char_t *rx_ring;                  //!< kernel mmap receive buffers
    osal_char_t *tx_ring;                  //!< kernel mmap send buffers

    off_t rx_ring_offset;
    off_t tx_ring_offset;

    osal_mutex_t hw_lock;           //!< transmit lock

    pool_t tx_high;                 //!< high priority datagrams
    pool_t tx_low;                  //!< low priority datagrams

    pool_entry_t *tx_send[256];     //!< sent datagrams
} hw_t;   

#ifdef __cplusplus
extern "C" {
#endif

//! open a new hw
/*!
 * \param pphw return hw 
 * \param devname ethernet device name
 * \param prio receive thread prio
 * \param cpumask receive thread cpumask
 * \param mmap_packets  0 - using traditional send/recv, 1...n number of mmaped kernel packet buffers
 * \return 0 or negative error code
 */
int hw_open(hw_t **pphw, const osal_char_t *devname, int prio, int cpumask, int mmap_packets);

//! destroys a hw
/*!
 * \param phw hw handle
 * \return 0 or negative error code
 */
int hw_close(hw_t *phw);

//! start sending queued ethercat datagrams
/*!
 * \param phw hardware handle
 * \return 0 or error code
 */
int hw_tx(hw_t *phw);

#ifdef __cplusplus
}
#endif

#endif // LIBETHERCAT_HW_H

