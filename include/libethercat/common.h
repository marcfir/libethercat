/**
 * \file common.h
 *
 * \author Robert Burger <robert.burger@dlr.de>
 *
 * \date 23 Nov 2016
 *
 * \brief ethercat master common stuff
 *
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

#ifndef LIBETHERCAT_COMMON_H
#define LIBETHERCAT_COMMON_H

#include <stdint.h>
#include <pthread.h>

#define PACKED __attribute__((__packed__))

#ifndef min
#define min(a, b)  ((a) < (b) ? (a) : (b))
#endif

#define ec_min(a, b)  ((a) < (b) ? (a) : (b))

#define free_resource(a) {  \
    if ((a) != NULL) {      \
        (void)free((a));          \
        (a) = NULL;         \
    } }

#define alloc_resource(a, type, len) {      \
    if ((len) > 0u) {                       \
        (a) = (type *)malloc((len));        \
        (void)memset((a), 0u, (len)); } }

#define EC_MAX_DATA 4096u

//typedef union ec_data {
//    uint8_t  bdata[EC_MAX_DATA]; /* variants for easy data access */
//    uint16_t wdata[EC_MAX_DATA>>1u];
//    uint32_t ldata[EC_MAX_DATA>>2u];
//} ec_data_t;

typedef uint8_t ec_data_t[EC_MAX_DATA]; /* variants for easy data access */

//! process data structure
typedef struct ec_pd {
    uint8_t *pd;        //!< pointer to process data
    size_t len;         //!< process data length
} ec_pd_t;

typedef uint16_t ec_state_t;
#define EC_STATE_UNKNOWN     (0x0000u)       //!< \brief unknown state
#define EC_STATE_INIT        (0x0001u)       //!< \brief EtherCAT INIT state
#define EC_STATE_PREOP       (0x0002u)       //!< \brief EtherCAT PREOP state
#define EC_STATE_BOOT        (0x0003u)       //!< \brief EtherCAT BOOT state
#define EC_STATE_SAFEOP      (0x0004u)       //!< \brief EtherCAT SAFEOP state
#define EC_STATE_OP          (0x0008u)       //!< \brief EtherCAT OP state
#define EC_STATE_MASK        (0x000Fu)       //!< \brief EtherCAT state mask
#define EC_STATE_ERROR       (0x0010u)       //!< \brief EtherCAT ERROR
#define EC_STATE_RESET       (0x0010u)       //!< \brief EtherCAT ERROR reset

#ifdef __VXWORKS__ 
char *strndup(const char *s, size_t n);
#endif

//#define check_ret(cmd) { if ((cmd) != 0) { ec_log(1, __func__, #cmd " returned error\n"); } }

#endif // LIBETHERCAT_COMMON_H

