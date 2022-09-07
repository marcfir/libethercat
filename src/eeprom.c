/**
 * \file eeprom.c
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
 * If not, see <www.gnu.org/licenses/>.
 */

#include "config.h"

#include "libethercat/eeprom.h"
#include "libethercat/ec.h"
#include "libethercat/memory.h"
#include "libethercat/error_codes.h"

#include <assert.h>
#include <string.h>

// cppcheck-suppress misra-c2012-20.10
#define SII_REG(ac, adr, val)                                          \
    cnt = 100u;                                                        \
    do { ret = ec_fp##ac(pec, pec->slaves[slave].fixed_address, (adr), \
                (osal_uint8_t *)&(val), sizeof(val), &wkc);                 \
    } while ((--cnt > 0u) && (wkc != 1u) && (ret == EC_OK));

// set eeprom control to pdi
int ec_eeprom_to_pdi(ec_t *pec, osal_uint16_t slave) {
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);

    int ret = EC_OK;
    osal_uint16_t wkc;
    osal_uint16_t cnt = 10u;
    osal_uint8_t eepctl = 2u;

    eepctl = 1; 
    SII_REG(wr, EC_REG_EEPCFG, eepctl);
    if ((ret != EC_OK) || (cnt == 0u)) {
        ret = EC_ERROR_EEPROM_CONTROL_TO_PDI;
    }

    return ret;
}

// set eeprom control to ec
int ec_eeprom_to_ec(struct ec *pec, osal_uint16_t slave) {
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);

    int ret = EC_OK;
    osal_uint16_t wkc;
    osal_uint16_t cnt = 10;
    osal_uint8_t eepctl = 2;
    
    SII_REG(rd, EC_REG_EEPCFG, eepctl);
    if ((ret != EC_OK) || (cnt == 0u)) {
        ec_log(1, __func__, "slave %2d: unable to get eeprom config/control\n", slave);
        ret = EC_ERROR_EEPROM_CONTROL_TO_EC;
    }

    if (ret == EC_OK) {
        if (((eepctl & 0x0001u) == 0x0000u) && ((eepctl & 0x0100u) == 0x0000u)) {
        } else {
            // ECAT assigns EEPROM interface to ECAT by writing 0x0500[0]=0
            eepctl = 0;
            SII_REG(wr, EC_REG_EEPCFG, eepctl);
            if ((ret != EC_OK) || (cnt == 0u)) {
                ec_log(1, __func__, "slave %2d did not accept assigning EEPROM to PDI\n", slave);
                ret = EC_ERROR_EEPROM_CONTROL_TO_EC;
            }
        }
    }

    if (ret == EC_OK) {
        SII_REG(rd, EC_REG_EEPCFG, eepctl);
        if ((ret != EC_OK) || (cnt == 0u)) {
            ec_log(1, __func__, "slave %2d: unable to get eeprom config/control\n", slave);
            ret = EC_ERROR_EEPROM_CONTROL_TO_EC;
        } else if (((eepctl & 0x0001u) == 0x0000u) && ((eepctl & 0x0100u) == 0x0000u)) {
            // ECAT has EEPROM control
        } else {
            ec_log(1, __func__, "slave %2d: failed setting eeprom to EtherCAT: eepctl %04X\n", eepctl);
        }
    }

    return ret;
}

// read 32-bit word of eeprom
int ec_eepromread(ec_t *pec, osal_uint16_t slave, osal_uint32_t eepadr, osal_uint32_t *data) {
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);
    assert(data != NULL);
   
    int ret = EC_OK;
    int retry_cnt = 100;
    osal_uint16_t wkc = 0;
    osal_uint16_t eepcsr = 0x0100; // read access
    
    ret = ec_eeprom_to_ec(pec, slave);
    
    // 1. Check if the Busy bit of the EEPROM Status register is 
    // cleared (0x0502[15]=0) and the EEPROM interface is not busy, 
    // otherwise wait until the EEPROM interface is not busy anymore.
    if (ret == EC_OK) {
        do {
            eepcsr = 0;
            ret = ec_fprd(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                    (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_READ", "reading eepctl failed, wkc %d\n", wkc);
                ret = EC_ERROR_EEPROM_READ_ERROR;
            }
        } while (((eepcsr & 0x0100u) != 0u) && (ret == EC_OK));
    } 

    if (ret == EC_OK) {
        ret = ec_fpwr(pec, pec->slaves[slave].fixed_address, EC_REG_EEPADR,
                (osal_uint8_t *)&eepadr, sizeof(eepadr), &wkc);

        if ((ret == EC_OK) && (wkc != 1u)) {
            ec_log(1, "EEPROM_READ", "writing eepadr failed\n");
            ret = EC_ERROR_EEPROM_READ_ERROR;
        }
    }

    if (ret == EC_OK) {
        eepcsr = 0x0100;
        ret = ec_fpwr(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);
        if ((ret == EC_OK) && (wkc != 1u)) {
            ec_log(1, "EEPROM_READ", "wirting eepctl failed\n");
            ret = EC_ERROR_EEPROM_READ_ERROR;
        }
    }

    // 7. Wait until the Busy bit of the EEPROM Status register is cleared
    if (ret == EC_OK) {
        retry_cnt = 100;
        do {
            eepcsr = 0;
            ret = ec_fprd(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                    (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_READ", "reading eepctl failed, wkc %d\n", wkc);
                ret = EC_ERROR_EEPROM_READ_ERROR;
            }
        } while (((wkc == 0u) || (eepcsr & 0x8000u)) && (ret == EC_OK));
    }

    if (ret == EC_OK) {
        *data = 0;
        ret = ec_fprd(pec, pec->slaves[slave].fixed_address, EC_REG_EEPDAT,
                (osal_uint8_t *)data, sizeof(*data), &wkc);
        if ((ret == EC_OK) && (wkc != 1u)) {
            ec_log(1, "EEPROM_READ", "reading data failed\n");
            ret = EC_ERROR_EEPROM_READ_ERROR;
        }
    }
    
    // 8. Check the Error bits of the EEPROM Status register. The Error bits 
    // are cleared by clearing the command register. Retry command 
    // (back to step 5) if EEPROM acknowledge was missing. If necessary, 
    // wait some time before retrying to allow slow EEPROMs to store the data 
    // internally
    if (ret == EC_OK) {
        if ((eepcsr & 0x0100u) != 0u) {
            ec_log(10, "EEPROM_READ", "write in progress\n");
            ret = EC_ERROR_EEPROM_WRITE_IN_PROGRESS;
        } else if ((eepcsr & 0x4000u) != 0u) {
            ec_log(1, "EEPROM_READ", "error write enable\n");
            ret = EC_ERROR_EEPROM_WRITE_ENABLE;
        } else if ((eepcsr & 0x2000u) != 0u) {
            ret = EC_ERROR_EEPROM_READ_ERROR;
        } else if ((eepcsr & 0x0800u) != 0u) {
            ec_log(1, "EEPROM_READ", "checksum error at in ESC configuration area\n");
            ret = EC_ERROR_EEPROM_CHECKSUM;
        } else {}
    }

    if (ret == EC_OK) {
        ret = ec_eeprom_to_pdi(pec, slave);
    }

    return ret;
}

// write 32-bit word of eeprom
int ec_eepromwrite(ec_t *pec, osal_uint16_t slave, osal_uint32_t eepadr, osal_uint16_t *data) {
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);
    assert(data != NULL);

    int ret = EC_OK;
    int retry_cnt = 100;
    osal_uint16_t wkc = 0;
    osal_uint16_t eepcsr = 0x0100; // write access
    
    ret = ec_eeprom_to_ec(pec, slave);
    
    // 1. Check if the Busy bit of the EEPROM Status register is 
    // cleared (0x0502[15]=0) and the EEPROM interface is not busy, 
    // otherwise wait until the EEPROM interface is not busy anymore.
    retry_cnt = 100;
    if (ret == EC_OK) {
        do {
            eepcsr = 0;
            ret = ec_fprd(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                    (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_WRITE", "waiting for eeprom !busy failed, "
                        "wkc %d\n", wkc);
                ret = EC_ERROR_EEPROM_WRITE_ERROR;
            }
        } while (((wkc == 0u) || ((eepcsr & 0x8000u) != 0x0000u)) && (ret == EC_OK));
    }

    // 2. Check if the Error bits of the EEPROM Status register are 
    // cleared. If not, write “000” to the command register 
    // (register 0x0502 bits [10:8]).
    if (ret == EC_OK) {
        while ((wkc == 0u) || ((eepcsr & 0x6000u) != 0u)) { 
            // we ignore crc errors on write .... 0x6800)
            // error bits set, clear first
            eepcsr = 0x0000u;
            do {
                ret = ec_fpwr(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                        (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);
            } while ((ret == EC_OK) && (wkc == 0u));

            if (ret == EC_OK) {
                ret = ec_fprd(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                    (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);
            }
        }
    }

    // 3. Write EEPROM word address to EEPROM Address register
    retry_cnt = 100;
    if (ret == EC_OK) {
        do {
            ret = ec_fpwr(pec, pec->slaves[slave].fixed_address, EC_REG_EEPADR,
                    (osal_uint8_t *)&eepadr, sizeof(eepadr), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_WRITE", "writing eepadr failed, wkc %d\n", wkc);
                ret = EC_ERROR_EEPROM_WRITE_IN_PROGRESS;
            }
        } while ((ret == EC_OK) && (wkc == 0u));
    }

    // 4. Write command only: put write data into EEPROM Data register 
    // (1 word/2 byte only).
    retry_cnt = 100;
    if (ret == EC_OK) {
        do {
            ret = ec_fpwr(pec, pec->slaves[slave].fixed_address, EC_REG_EEPDAT,
                    (osal_uint8_t *)data, sizeof(*data), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_WRITE", "writing data failed\n");
                ret = EC_ERROR_EEPROM_WRITE_ERROR;
            }
        } while ((ret == EC_OK) && (wkc == 0u));
    }

    // 5. Issue command by writing to Control register.  
    // b) For a write command, write 1 into Write Enable bit 0x0502[0]
    // and 010 into Command Register 0x0502[10:8]. Both bits have to be 
    // written in one frame. The Write enable bit realizes a write protection 
    // mechanism. It is valid for subsequent EEPROM commands issued in the 
    // same frame and self-clearing afterwards. The Write enable bit needs 
    // not to be written from PDI if it controls the EEPROM interface.
    eepcsr = 0x0201;
    retry_cnt = 100;
    if (ret == EC_OK) {
        do {
            ret = ec_fpwr(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                    (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_WRITE", "wirting eepctl failed\n");
                ret = EC_ERROR_EEPROM_WRITE_ERROR;
            }
        } while ((ret == EC_OK) && (wkc == 0u));
    }

    // 6. The command is executed after the EOF if the EtherCAT frame had 
    // no errors. With PDI control, the command is executed immediately.

    // 7. Wait until the Busy bit of the EEPROM Status register is cleared
    if (ret == EC_OK) {
        retry_cnt = 100;
        do {
            eepcsr = 0;
            ret = ec_fprd(pec, pec->slaves[slave].fixed_address, EC_REG_EEPCTL,
                    (osal_uint8_t *)&eepcsr, sizeof(eepcsr), &wkc);

            retry_cnt--;
            if ((ret == EC_OK) && (retry_cnt == 0)) {
                ec_log(1, "EEPROM_WRITE", "reading eepctl failed, wkc %d\n", wkc);
                ret = EC_ERROR_EEPROM_WRITE_ERROR;
            }
        } while (((wkc == 0u) || ((eepcsr & 0x8000u) != 0u)) && (ret == EC_OK));
    }

    // 8. Check the Error bits of the EEPROM Status register. The Error bits 
    // are cleared by clearing the command register. Retry command
    // (back to step 5) if EEPROM acknowledge was missing. If necessary, 
    // wait some time before retrying to allow slow EEPROMs to store the 
    // data internally
    if (ret == EC_OK) {
        if ((eepcsr & 0x0100u) != 0u) { 
            ec_log(1, "EEPROM_WRITE", "write in progress\n");
            ret = EC_ERROR_EEPROM_WRITE_IN_PROGRESS;
        } else if ((eepcsr & 0x4000u) != 0u) {
            ec_log(1, "EEPROM_WRITE", "error write enable\n");
            ret = EC_ERROR_EEPROM_WRITE_ENABLE;
        } else if ((eepcsr & 0x2000u) != 0u) {
            ret = EC_ERROR_EEPROM_WRITE_ERROR;
        } else if ((eepcsr & 0x0800u) != 0u) {
            ec_log(1, "EEPROM_WRITE", 
                    "checksum error at in ESC configuration area\n");
            ret = EC_ERROR_EEPROM_CHECKSUM;
        } else {}
    }

    if (ret == EC_OK) {
        ret = ec_eeprom_to_pdi(pec, slave);
    }

    return ret;
}

// read a burst of eeprom
int ec_eepromread_len(ec_t *pec, osal_uint16_t slave, osal_uint32_t eepadr, 
        osal_uint8_t *buf, osal_size_t buflen) 
{
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);
    assert(buf != NULL);

    off_t offset = 0;
    int ret = EC_OK;
    
    while (offset < buflen) {
        osal_uint8_t val[4];
        int i;

        // cppcheck-suppress misra-c2012-11.3
        ret = ec_eepromread(pec, slave, eepadr+(offset/2u), (osal_uint32_t *)&val[0]);
        if (ret != EC_OK) {
            break;
        }

        i = 0;
        while ((offset < buflen) && (i < 4)) {
            buf[offset] = val[i];
            offset++;
            i++;
        }
    }

    return ret;
};

// write a burst of eeprom
int ec_eepromwrite_len(ec_t *pec, osal_uint16_t slave, osal_uint32_t eepadr, 
        const osal_uint8_t *buf, osal_size_t buflen) 
{
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);
    assert(buf != NULL);

    off_t offset = 0;
    int i;
    int ret = EC_OK;

    while (offset < (buflen/2u)) {
        osal_uint8_t val[2];
        for (i = 0; i < 2; ++i) {
            val[i] = buf[(offset*2)+i];
        }
                
        ec_log(100, __func__, "slave %2d, writing adr %d : 0x%04X\n", 
                        slave, eepadr+offset, *(osal_uint16_t *)&val);

        do {
            ret = ec_eepromwrite(pec, slave, eepadr+offset, (osal_uint16_t *)&val);
        } while (ret != EC_OK);

        offset +=1u;
    }

    return ret;
};

// read out whole eeprom and categories
void ec_eeprom_dump(ec_t *pec, osal_uint16_t slave) {
    assert(pec != NULL);
    assert(slave < pec->slave_cnt);

    off_t cat_offset = EC_EEPROM_ADR_CAT_OFFSET;
    osal_uint32_t value32 = 0;
    
    ec_slave_ptr(slv, pec, slave);

    if (slv->eeprom.read_eeprom == 0) {
        osal_uint16_t size;

#define ec_read_eeprom(adr, mem) \
        ec_eepromread_len(pec, slave, (adr), (osal_uint8_t *)&(mem), sizeof(mem));
#define do_eeprom_log(...) \
        if (pec->eeprom_log != 0) { ec_log(__VA_ARGS__); }

        // read soem eeprom values
        (void)ec_read_eeprom(EC_EEPROM_ADR_VENDOR_ID, slv->eeprom.vendor_id);
        (void)ec_read_eeprom(EC_EEPROM_ADR_PRODUCT_CODE, slv->eeprom.product_code);
        (void)ec_read_eeprom(EC_EEPROM_ADR_MBX_SUPPORTED, slv->eeprom.mbx_supported);
        (void)ec_read_eeprom(EC_EEPROM_ADR_SIZE, value32);
        (void)ec_read_eeprom(EC_EEPROM_ADR_STD_MBX_RECV_OFF, slv->eeprom.mbx_receive_offset);
        (void)ec_read_eeprom(EC_EEPROM_ADR_STD_MBX_RECV_SIZE, slv->eeprom.mbx_receive_size);
        (void)ec_read_eeprom(EC_EEPROM_ADR_STD_MBX_SEND_OFF, slv->eeprom.mbx_send_offset);
        (void)ec_read_eeprom(EC_EEPROM_ADR_STD_MBX_SEND_SIZE, slv->eeprom.mbx_send_size);
        (void)ec_read_eeprom(EC_EEPROM_ADR_BOOT_MBX_RECV_OFF, slv->eeprom.boot_mbx_receive_offset);
        (void)ec_read_eeprom(EC_EEPROM_ADR_BOOT_MBX_RECV_SIZE, slv->eeprom.boot_mbx_receive_size);
        (void)ec_read_eeprom(EC_EEPROM_ADR_BOOT_MBX_SEND_OFF, slv->eeprom.boot_mbx_send_offset);
        (void)ec_read_eeprom(EC_EEPROM_ADR_BOOT_MBX_SEND_SIZE, slv->eeprom.boot_mbx_send_size);

        slv->eeprom.read_eeprom = 1;

        size = (osal_uint16_t)(((value32 & 0x0000FFFFu) + 1u) * 125u); // convert kbit to byte
        if (size > 128u) {
            osal_uint16_t cat_type;
            do {
                int ret = ec_read_eeprom(cat_offset, value32);
                if (ret != 0) {
                    break;
                }

                cat_type = (osal_uint16_t)(value32 & 0x0000FFFFu);
                osal_uint16_t cat_len  = (osal_uint16_t)((value32 & 0xFFFF0000u) >> 16u);

                switch (cat_type) {
                    default: 
                    case EC_EEPROM_CAT_END:
                    case EC_EEPROM_CAT_NOP:
                        break;
                    case EC_EEPROM_CAT_STRINGS: {
                        do_eeprom_log(10, "EEPROM_STRINGS", "slave %2d: cat_len %d\n", slave, cat_len);

                        // cppcheck-suppress misra-c2012-21.3
                        osal_uint8_t *buf = (osal_uint8_t *)ec_malloc((cat_len * 2u) + 1u);
                        buf[cat_len * 2u] = 0u;
                        (void)ec_eepromread_len(pec, slave, cat_offset+2, buf, cat_len * 2u);

                        osal_uint32_t local_offset = 0;
                        osal_uint32_t i;
                        slv->eeprom.strings_cnt = buf[local_offset];
                        local_offset++;

                        do_eeprom_log(10, "EEPROM_STRINGS", "slave %2d: stored strings %d\n", slave, slv->eeprom.strings_cnt);

                        if (!slv->eeprom.strings_cnt) {
                            // cppcheck-suppress misra-c2012-21.3
                            ec_free(buf);
                            break;
                        }

                        // cppcheck-suppress misra-c2012-21.3
                        slv->eeprom.strings = (osal_char_t **)ec_malloc(sizeof(osal_char_t *) * slv->eeprom.strings_cnt);

                        for (i = 0; i < slv->eeprom.strings_cnt; ++i) {
                            osal_uint8_t string_len = buf[local_offset];
                            local_offset++;

                            // cppcheck-suppress misra-c2012-21.3
                            slv->eeprom.strings[i] = (osal_char_t *)ec_malloc(sizeof(osal_char_t) * (string_len + 1u));
                            (void)strncpy(slv->eeprom.strings[i], (osal_char_t *)&buf[local_offset], string_len);
                            local_offset += string_len;

                            slv->eeprom.strings[i][string_len] = '\0';

                            do_eeprom_log(10, "EEPROM_STRINGS", 
                                    "          string %2d, length %2d : %s\n", 
                                    i, string_len, slv->eeprom.strings[i]);
                            if (local_offset > (cat_len * 2u)) {
                                do_eeprom_log(5, "EEPROM_STRINGS", 
                                        "          something wrong in eeprom "
                                        "string section\n");
                                break;
                            }
                        }

                        // cppcheck-suppress misra-c2012-21.3
                        ec_free(buf);
                        break;
                    }
                    case EC_EEPROM_CAT_DATATYPES:
                        do_eeprom_log(10, "EEPROM_DATATYPES", "slave %2d:\n", slave);
                        break;
                    case EC_EEPROM_CAT_GENERAL: {
                        do_eeprom_log(10, "EEPROM_GENERAL", "slave %2d:\n", slave);

                        (void)ec_read_eeprom(cat_offset+2, slv->eeprom.general);

                        do_eeprom_log(10, "EEPROM_GENERAL", 
                                "          group_idx %d, img_idx %d, "
                                "order_idx %d, name_idx %d\n", 
                                slave, slv->eeprom.general.group_idx,
                                slv->eeprom.general.img_idx,
                                slv->eeprom.general.order_idx,
                                slv->eeprom.general.name_idx);
                        break;
                    }
                    case EC_EEPROM_CAT_FMMU: {
                        do_eeprom_log(10, "EEPROM_FMMU", "slave %2d: entries %d\n", 
                                slave, cat_len);

                        // skip cat type and len
                        osal_uint32_t local_offset = cat_offset + 2u;
                        slv->eeprom.fmmus_cnt = cat_len * 2u;

                        if (!slv->eeprom.fmmus_cnt) {
                            break;
                        }

                        // alloc fmmus
                        // cppcheck-suppress misra-c2012-21.3
                        slv->eeprom.fmmus = (ec_eeprom_cat_fmmu_t *)ec_malloc(
                                sizeof(ec_eeprom_cat_fmmu_t) * slv->eeprom.fmmus_cnt);

                        osal_uint32_t fmmu_idx = 0;
                        while (local_offset < (cat_offset + cat_len + 2u)) {
                            osal_uint32_t i;

                            (void)ec_read_eeprom(local_offset, value32);
                            osal_uint8_t tmp[4];
                            (void)memcpy(&tmp[0], (osal_uint8_t *)&value32, 4);

                            i = 0u;
                            while ((i < 4u) && (i < (cat_len * 2u))) {
                                if ((fmmu_idx < slv->fmmu_ch) && (tmp[i] >= 1u) && (tmp[i] <= 3u)) 
                                {
                                    slv->fmmu[fmmu_idx].type = tmp[i];
                                    slv->eeprom.fmmus[fmmu_idx].type = tmp[i];

                                    do_eeprom_log(10, "EEPROM_FMMU", "          fmmu%d, type %d\n", fmmu_idx, tmp[i]);
                                }

                                i++;
                                fmmu_idx++;
                            }

                            local_offset += 2u;
                        }
                        break;
                    }
                    case EC_EEPROM_CAT_SM: {
                        do_eeprom_log(10, "EEPROM_SM", "slave %2d: entries %d\n", 
                                slave, cat_len/(sizeof(ec_eeprom_cat_sm_t)/2u));

                        // skip cat type and len
                        osal_uint32_t j = 0;
                        off_t local_offset = cat_offset + 2;
                        slv->eeprom.sms_cnt = cat_len/(sizeof(ec_eeprom_cat_sm_t)/2u);

                        if (!slv->eeprom.sms_cnt) {
                            break;
                        }

                        // alloc sms
                        // cppcheck-suppress misra-c2012-21.3
                        slv->eeprom.sms = (ec_eeprom_cat_sm_t *)ec_malloc(
                                sizeof(ec_eeprom_cat_sm_t) * slv->eeprom.sms_cnt);

                        // reallocate if we have more sm that previously declared
                        if ((cat_len/(sizeof(ec_eeprom_cat_sm_t) / 2u)) > slv->sm_ch) {
                            if (slv->sm != NULL) {
                                // cppcheck-suppress misra-c2012-21.3
                                ec_free(slv->sm);
                            }

                            slv->sm_ch = cat_len/(sizeof(ec_eeprom_cat_sm_t)/2u);
                            // cppcheck-suppress misra-c2012-21.3
                            slv->sm = (ec_slave_sm_t *)ec_malloc(slv->sm_ch * 
                                    sizeof(ec_slave_sm_t));
                            (void)memset(slv->sm, 0, slv->sm_ch * sizeof(ec_slave_sm_t));
                        }

                        while (local_offset < (cat_offset + cat_len + 2u)) {
                            (void)ec_read_eeprom(local_offset, slv->eeprom.sms[j]);
                            local_offset += (off_t)(sizeof(ec_eeprom_cat_sm_t) / 2u);

                            if (slv->sm[j].adr == 0u) {
                                slv->sm[j].adr = slv->eeprom.sms[j].adr;
                                slv->sm[j].len = slv->eeprom.sms[j].len;
                                slv->sm[j].flags = (slv->eeprom.sms[j].activate << 16)
                                    | slv->eeprom.sms[j].ctrl_reg;

                                do_eeprom_log(10, "EEPROM_SM", 
                                        "          sm%d adr 0x%X, len %d, flags "
                                        "0x%X\n", j, slv->sm[j].adr, slv->sm[j].len, 
                                        slv->sm[j].flags);
                            } else {
                                do_eeprom_log(10, "EEPROM_SM", "          sm%d adr "
                                        "0x%X, len %d, flags 0x%X\n", j, 
                                        slv->eeprom.sms[j].adr, slv->eeprom.sms[j].len,
                                        (slv->eeprom.sms[j].activate << 16) | 
                                        slv->eeprom.sms[j].ctrl_reg);

                                do_eeprom_log(10, "EEPROM_SM", 
                                        "          sm%d already set by user\n", j);
                            }

                            j++;
                        }
                        break;
                    }
                    case EC_EEPROM_CAT_TXPDO: {
                        do_eeprom_log(100, "EEPROM_TXPDO", "slave %2d:\n", slave);

                        // skip cat type and len
                        osal_uint32_t j = 0;
                        osal_size_t local_offset = cat_offset + 2u;
                        if (!cat_len) {
                            break;
                        }

                        // freeing tailq first
                        ec_eeprom_cat_pdo_t *pdo = TAILQ_FIRST(&slv->eeprom.txpdos);
                        while (pdo != NULL) {
                            TAILQ_REMOVE(&slv->eeprom.txpdos, pdo, qh);
                            // cppcheck-suppress misra-c2012-21.3
                            ec_free(pdo);
                            pdo = TAILQ_FIRST(&slv->eeprom.txpdos);
                        }

                        do {
                            // read pdo
                            // cppcheck-suppress misra-c2012-21.3
                            pdo = (ec_eeprom_cat_pdo_t *)ec_malloc(sizeof(ec_eeprom_cat_pdo_t));
                            (void)memset((osal_uint8_t *)pdo, 0, sizeof(ec_eeprom_cat_pdo_t));
                            (void)ec_eepromread_len(pec, slave, local_offset, 
                                    (osal_uint8_t *)pdo, EC_EEPROM_CAT_PDO_LEN);
                            local_offset += (osal_size_t)(EC_EEPROM_CAT_PDO_LEN / 2u);

                            do_eeprom_log(10, "EEPROM_TXPDO", "          0x%04X, entries %d\n",
                                    pdo->pdo_index, pdo->n_entry);

                            if (pdo->n_entry > 0u) {
                                // alloc entries
                                // cppcheck-suppress misra-c2012-21.3
                                pdo->entries = (ec_eeprom_cat_pdo_entry_t *)ec_malloc(pdo->n_entry * 
                                        sizeof(ec_eeprom_cat_pdo_entry_t));

                                for (j = 0; j < pdo->n_entry; ++j) {
                                    ec_eeprom_cat_pdo_entry_t *entry = &pdo->entries[j];
                                    (void)ec_eepromread_len(pec, slave, local_offset,
                                            (osal_uint8_t *)entry, 
                                            sizeof(ec_eeprom_cat_pdo_entry_t));

                                    local_offset += sizeof(ec_eeprom_cat_pdo_entry_t) / 2u;

                                    do_eeprom_log(10, "EEPROM_TXPDO", 
                                            "          0x%04X:%2d -> 0x%04X\n",
                                            pdo->pdo_index, j, entry->entry_index);
                                }
                            }

                            TAILQ_INSERT_TAIL(&slv->eeprom.txpdos, pdo, qh);
                        } while (local_offset < (cat_offset + cat_len + 2u)); 

                        break;
                    }
                    case EC_EEPROM_CAT_RXPDO: {
                        do_eeprom_log(10, "EEPROM_RXPDO", "slave %2d:\n", slave);

                        // skip cat type and len
                        osal_uint32_t j = 0u;
                        osal_size_t local_offset = cat_offset + 2u;
                        if (!cat_len) {
                            break;
                        }

                        // freeing tailq first
                        ec_eeprom_cat_pdo_t *pdo = TAILQ_FIRST(&slv->eeprom.rxpdos);
                        while (pdo != NULL) {
                            TAILQ_REMOVE(&slv->eeprom.rxpdos, pdo, qh);
                            // cppcheck-suppress misra-c2012-21.3
                            ec_free(pdo);
                            pdo = TAILQ_FIRST(&slv->eeprom.rxpdos);
                        }

                        do {
                            // read pdo
                            // cppcheck-suppress misra-c2012-21.3
                            pdo = (ec_eeprom_cat_pdo_t *)ec_malloc(sizeof(ec_eeprom_cat_pdo_t));
                            (void)ec_eepromread_len(pec, slave, local_offset, 
                                    (osal_uint8_t *)pdo, EC_EEPROM_CAT_PDO_LEN);
                            local_offset += (osal_size_t)(EC_EEPROM_CAT_PDO_LEN / 2u);

                            do_eeprom_log(10, "EEPROM_RXPDO", "          0x%04X, entries %d\n",
                                    pdo->pdo_index, pdo->n_entry);

                            if (pdo->n_entry > 0u) {
                                // alloc entries
                                // cppcheck-suppress misra-c2012-21.3
                                pdo->entries = (ec_eeprom_cat_pdo_entry_t *)ec_malloc(pdo->n_entry * 
                                        sizeof(ec_eeprom_cat_pdo_entry_t));

                                for (j = 0; j < pdo->n_entry; ++j) {
                                    ec_eeprom_cat_pdo_entry_t *entry = &pdo->entries[j];
                                    (void)ec_eepromread_len(pec, slave, local_offset,
                                            (osal_uint8_t *)entry, 
                                            sizeof(ec_eeprom_cat_pdo_entry_t));

                                    local_offset += sizeof(ec_eeprom_cat_pdo_entry_t) / 2u;

                                    do_eeprom_log(10, "EEPROM_RXPDO", 
                                            "          0x%04X:%2d -> 0x%04X\n",
                                            pdo->pdo_index, j, entry->entry_index);
                                }
                            }

                            TAILQ_INSERT_TAIL(&slv->eeprom.rxpdos, pdo, qh);
                        } while (local_offset < (cat_offset + cat_len + 2u)); 

                        break;
                    }
                    case EC_EEPROM_CAT_DC: {
                        osal_uint32_t j = 0u;
                        osal_size_t local_offset = cat_offset + 2u;

                        do_eeprom_log(10, "EEPROM_DC", "slave %2d:\n", slave);

                        // freeing existing dcs ...
                        if (slv->eeprom.dcs > 0) {
                            // cppcheck-suppress misra-c2012-21.3
                            ec_free(slv->eeprom.dcs);
                            slv->eeprom.dcs = NULL;
                            slv->eeprom.dcs_cnt = 0;
                        }

                        // allocating new dcs
                        slv->eeprom.dcs_cnt = cat_len / (osal_size_t)(EC_EEPROM_CAT_DC_LEN / 2u);
                        // cppcheck-suppress misra-c2012-21.3
                        slv->eeprom.dcs = (ec_eeprom_cat_dc_t *)ec_malloc(EC_EEPROM_CAT_DC_LEN * slv->eeprom.dcs_cnt);

                        for (j = 0; j < slv->eeprom.dcs_cnt; ++j) {
                            ec_eeprom_cat_dc_t *dc = &slv->eeprom.dcs[j];
                            (void)ec_eepromread_len(pec, slave, local_offset,
                                    (osal_uint8_t *)dc, EC_EEPROM_CAT_DC_LEN);
                            local_offset += (osal_size_t)(EC_EEPROM_CAT_DC_LEN / 2u);

                            do_eeprom_log(10, "EEPROM_DC", "          cycle_time_0 %d, "
                                    "shift_time_0 %d, shift_time_1 %d, "
                                    "sync_0_cycle_factor %d, sync_1_cycle_factor %d, "
                                    "assign_active %d\n", 
                                    dc->cycle_time_0, dc->shift_time_0, 
                                    dc->shift_time_1, dc->sync_0_cycle_factor, 
                                    dc->sync_1_cycle_factor, dc->assign_active);                   
                        }

                        break;
                    }
                }

                cat_offset += cat_len + 2u; 

            } while (((cat_offset * 2u) < size) && (cat_type != EC_EEPROM_CAT_END));
        }
    
        slv->eeprom.read_eeprom = 1;
    }
}

