/**
 * \file eeprom.h
 *
 * \author Robert Burger <robert.burger@dlr.de>
 *
 * \date 24 Nov 2016
 *
 * \brief ethercat eeprom access fuctions
 *
 * These functions are used to ensure access to the EtherCAT
 * slaves EEPROM.
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

#ifndef __LIBETHERCAT_EEPROM_H__
#define __LIBETHERCAT_EEPROM_H__

#include "libethercat/common.h"
#include <stdlib.h>
#include <sys/queue.h>

//------------------ Category General ---------------

typedef struct PACKED ec_eeprom_cat_general {
    uint8_t group_idx;          //!< group information, index to STRING
    uint8_t img_idx;            //!< image name, index to STRING
    uint8_t order_idx;          //!< device order number, index to STRING
    uint8_t name_idx;           //!< device name, index to STRING
    uint8_t physical_layer;     //!< physical layer, 0 e-bus, 1, 100base-tx
    uint8_t can_open;           //!< coe support
    uint8_t file_access;        //!< foe support
    uint8_t ethernet;           //!< eoe support
    uint8_t soe_channels;       //!< supported soe channels
    uint8_t ds402_channels;     //!< supported ds402 channels
    uint8_t sysman_class;       //!< sys man ?
    uint8_t flags;              //!< eeprom flags
    uint16_t current_on_ebus;   //!< ebus current in [mA], negative = feed-in
} ec_eeprom_cat_general_t;
    
//------------------ Category PDO -------------------

typedef struct PACKED ec_eeprom_cat_pdo_entry {
    uint16_t entry_index;       //!< PDO entry index (CoE)
    uint8_t sub_index;          //!< PDO entry subindex 
    uint8_t entry_name_idx;     //!< name index in eeprom strings
    uint8_t data_type;          //!< data type
    uint8_t bit_len;            //!< length in bits
    uint16_t flags;             //!< PDO entry flags
} ec_eeprom_cat_pdo_entry_t;

typedef struct PACKED ec_eeprom_cat_pdo {
    uint16_t pdo_index;         //!< PDO index
    uint8_t n_entry;            //!< number of PDO entries
    uint8_t sm_nr;              //!< assigned sync manager
    uint8_t dc_sync;            //!< use distributed clocks
    uint8_t name_idx;           //!< name index in eeprom strings
    uint16_t flags;             //!< PDO flags
#define EC_EEPROM_CAT_PDO_LEN   8
    ec_eeprom_cat_pdo_entry_t *entries;
                                //!< PDO entries, (n_entry count)
    
    TAILQ_ENTRY(ec_eeprom_cat_pdo) qh;
                                //!< queue handle for PDO queue
} ec_eeprom_cat_pdo_t;

//! head to PDO queue
TAILQ_HEAD(ec_eeprom_cat_pdo_queue, ec_eeprom_cat_pdo);

//------------------ Category SM --------------------

//! eeprom sync manager settings
typedef struct PACKED ec_eeprom_cat_sm {
    uint16_t adr;               //!< physical start addres
    uint16_t len;               //!< length at physical start address
    uint8_t  ctrl_reg;          //!< control register init value
    uint8_t  status_reg;        //!< status register init value
    uint8_t  activate;          //!< activation flags
    uint8_t  pdi_ctrl;          //!< pdi control register
} PACKED ec_eeprom_cat_sm_t;

//------------------ Category DC --------------------

//! eeprom distributed clocks settings
typedef struct PACKED ec_eeprom_cat_dc {
    uint32_t cycle_time_0;          //!< cycle time sync0
    uint32_t shift_time_0;          //!< shift time sync0
    uint32_t shift_time_1;          //!< shift time sync1
    int16_t  sync_1_cycle_factor;   //!< cycle factor sync1
    uint16_t assign_active;         //!< activation flags
    int16_t  sync_0_cycle_factor;   //!< cycle factor sync0
    uint8_t  name_idx;              //!< name index in eeprom strings
    uint8_t  desc_idx;              //!< description index
    uint8_t  reserved[4];           //!< funny reserved bytes
#define EC_EEPROM_CAT_DC_LEN    24
} PACKED ec_eeprom_cat_dc_t;

//------------------ Category FMMU ------------------

//! eeporm fmmu description
typedef struct PACKED ec_eeprom_cat_fmmu {
    uint8_t type;                   //!< fmmu type
} PACKED ec_eeprom_cat_fmmu_t;
    
typedef struct eeprom_info {
    int read_eeprom;                //!< read eeprom while reaching PREOP state

    uint32_t vendor_id;             //!< vendor id
    uint32_t product_code;          //!< product code
    uint16_t mbx_supported;         //!< mailbox supported by slave

    uint16_t mbx_receive_offset;    //!< default mailbox receive offset
    uint16_t mbx_receive_size;      //!< default mailbox receive size
    uint16_t mbx_send_offset;       //!< default mailbox send offset
    uint16_t mbx_send_size;         //!< default mailbox send size
    
    uint16_t boot_mbx_receive_offset;
                                    //!< boot mailbox receive offset
    uint16_t boot_mbx_receive_size; //!< boot mailbox receive size
    uint16_t boot_mbx_send_offset;  //!< boot mailbox send offset
    uint16_t boot_mbx_send_size;    //!< boot mailbox send size

    ec_eeprom_cat_general_t general;//!< general category

    uint8_t strings_cnt;            //!< count of strings
    char **strings;                 //!< array of strings 

    uint8_t sms_cnt;                //!< count of sync manager settings
    ec_eeprom_cat_sm_t *sms;        //!< array of sync manager settings

    uint8_t fmmus_cnt;              //!< count of fmmu settings    
    ec_eeprom_cat_fmmu_t *fmmus;    //!< array of fmmu settings

    struct ec_eeprom_cat_pdo_queue txpdos;
                                    //!< queue with TXPDOs
    struct ec_eeprom_cat_pdo_queue rxpdos;
                                    //!< queue with RXPDOs

    uint8_t dcs_cnt;                //!< count of distributed clocks settings                            
    ec_eeprom_cat_dc_t *dcs;        //!< array of distributed clocks settings
} eeprom_info_t;

enum {
    EC_EEPROM_MBX_AOE = 0x01,       //! AoE mailbox support
    EC_EEPROM_MBX_EOE = 0x02,       //! EoE mailbox support
    EC_EEPROM_MBX_COE = 0x04,       //! CoE mailbox support
    EC_EEPROM_MBX_FOE = 0x08,       //! FoE mailbox support
    EC_EEPROM_MBX_SOE = 0x10,       //! SoE mailbox support
    EC_EEPROM_MBX_VOE = 0x20,       //! VoE mailbox support
};

enum {
    EC_EEPROM_ADR_VENDOR_ID          = 0x0008,  //!< offset vendor id
    EC_EEPROM_ADR_PRODUCT_CODE       = 0x000A,  //!< offset product code
    EC_EEPROM_ADR_BOOT_MBX_RECV_OFF  = 0x0014,  //!< offset mbx receive off
    EC_EEPROM_ADR_BOOT_MBX_RECV_SIZE = 0x0015,  //!< offset mbx receive size
    EC_EEPROM_ADR_BOOT_MBX_SEND_OFF  = 0x0016,  //!< offset mbx send off
    EC_EEPROM_ADR_BOOT_MBX_SEND_SIZE = 0x0017,  //!< offset mbx send size
    EC_EEPROM_ADR_STD_MBX_RECV_OFF   = 0x0018,  //!< offset boot mbx rcv off
    EC_EEPROM_ADR_STD_MBX_RECV_SIZE  = 0x0019,  //!< offset boot mbx rcv size
    EC_EEPROM_ADR_STD_MBX_SEND_OFF   = 0x001A,  //!< offset boot mbx send off
    EC_EEPROM_ADR_STD_MBX_SEND_SIZE  = 0x001B,  //!< offset boot mbx send size
    EC_EEPROM_ADR_MBX_SUPPORTED      = 0x001C,  //!< offset mailbox supported
    EC_EEPROM_ADR_SIZE               = 0x003E,  //!< offset eeprom size
    EC_EEPROM_ADR_CAT_OFFSET         = 0x0040,  //!< offset start of categories
};

enum {
    EC_EEPROM_CAT_NOP       = 0,            //!< category do nothing
    EC_EEPROM_CAT_STRINGS   = 10,           //!< category strings
    EC_EEPROM_CAT_DATATYPES = 20,           //!< category datatypes
    EC_EEPROM_CAT_GENERAL   = 30,           //!< category general
    EC_EEPROM_CAT_FMMU      = 40,           //!< category fmmus
    EC_EEPROM_CAT_SM        = 41,           //!< category sync managers
    EC_EEPROM_CAT_TXPDO     = 50,           //!< category TXPDOs
    EC_EEPROM_CAT_RXPDO     = 51,           //!< category RXPDOs
    EC_EEPROM_CAT_DC        = 60,           //!< category distributed clocks
    EC_EEPROM_CAT_END       = 0xFFFF        //!< category end identifier
};

#ifdef __cplusplus
extern "C" {
#elif defined my_little_dummy
}
#endif

// forward decl
struct ec;

//! set eeprom control to pdi
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 * \return 0 on success
 */
int ec_eeprom_to_pdi(struct ec *pec, uint16_t slave);

//! set eeprom control to ec
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 * \return 0 on success
 */
int ec_eeprom_to_ec(struct ec *pec, uint16_t slave);

//! read 32-bit word of eeprom
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 * \param eepadr address in eeprom
 * \param returns data value
 * \return 0 on success
 */
int ec_eepromread(struct ec *pec, uint16_t slave, 
        uint32_t eepadr, uint32_t *data);

//! write 32-bit word to eeprom
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 * \param eepadr address in eeprom
 * \param data data to write
 * \return 0 on success
 */
int ec_eepromwrite(struct ec *pec, uint16_t slave, 
        uint32_t eepadr, uint16_t *data);

//! read a burst of eeprom
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 * \param eepadr address in eeprom
 * \param buf return buffer
 * \param buflen length in bytes to return
 * \return 0 on success
 */
int ec_eepromread_len(struct ec *pec, uint16_t slave, 
        uint32_t eepadr, uint8_t *buf, size_t buflen);

//! write a burst of eeprom
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 * \param eepadr address in eeprom
 * \param buf return buffer
 * \param buflen length in bytes to return
 * \return 0 on success
 */
int ec_eepromwrite_len(struct ec *pec, uint16_t slave, 
        uint32_t eepadr, uint8_t *buf, size_t buflen);

//! read out whole eeprom and categories
/*!
 * \param pec pointer to ethercat master
 * \param slave ethercat slave number
 */
void ec_eeprom_dump(struct ec *pec, uint16_t slave);

#ifdef my_little_dummy
{
#elif defined __cplusplus
}
#endif

#endif // __LIBETHERCAT_EEPROM_H__

