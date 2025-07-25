#ifdef HAVE_CONFIG_H
#include "libethercat/config.h"
#endif

#include "libethercat/ec.h"
#include "libethercat/mii.h"

#include <stdio.h>

#if LIBETHERCAT_HAVE_UNISTD_H == 1
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>

#if LIBETHERCAT_HAVE_SYS_STAT_H == 1
#include <sys/stat.h>
#endif

#if LIBETHERCAT_HAVE_FCNTL_H == 1
#include <fcntl.h>
#endif

#include <stdarg.h>

#if LIBETHERCAT_BUILD_DEVICE_FILE == 1
#include <libethercat/hw_file.h>
static struct hw_file hw_file;
#endif
#if LIBETHERCAT_BUILD_DEVICE_BPF == 1
#include <libethercat/hw_bpf.h>
static struct hw_bpf hw_bpf;
#endif
#if LIBETHERCAT_BUILD_DEVICE_PIKEOS == 1
#include <libethercat/hw_pikeos.h>
static struct hw_pikeos hw_pikeos;
#endif
#if LIBETHERCAT_BUILD_DEVICE_SOCK_RAW_LEGACY == 1
#include <libethercat/hw_sock_raw.h>
static struct hw_sock_raw hw_sock_raw;
#endif
#if LIBETHERCAT_BUILD_DEVICE_SOCK_RAW_MMAPED == 1
#include <libethercat/hw_sock_raw_mmaped.h>
static struct hw_sock_raw_mmaped hw_sock_raw_mmaped;
#endif


void no_log(int lvl, void *user, const char *format, ...) 
{};


int usage(int argc, char **argv) {
    printf("%s -i|--interface <intf> [-p|--propagation-delay]\n", argv[0]);
    return 0;
}

void propagation_delays(ec_t *pec) {
    int slave, ret = ec_set_state(pec, EC_STATE_INIT);
    ec_dc_config(pec);

    printf("propagation delays for distributed clocks: \n\n");

    printf("ethercat master\n");

    ec_create_pd_groups(pec, 1);
    
    for(slave = 0; slave < ec_get_slave_count(pec); ++slave) {
#define print_prefix() {                                    \
        int tmp_parent = pec->slaves[slave].parent;         \
        while (tmp_parent >= 0) {                           \
            printf("|   ");                                 \
            tmp_parent = pec->slaves[tmp_parent].parent;    \
        } }

        ec_slave_t *slv = &pec->slaves[slave];
        slv->assigned_pd_group = 0;

        print_prefix();
        printf("|---");
        printf("slave %2d: ", 
                slave);

        if ((slv->eeprom.general.name_idx > 0) &&
                (slv->eeprom.general.name_idx <= slv->eeprom.strings_cnt)) {
            printf("%s", slv->eeprom.strings[slv->eeprom.general.name_idx-1]);
        }
        printf("\n");
        

        print_prefix();
        printf("|   ");
        printf("|         dc support %X, propagation delay %d [ns]\n", 
                (slv->features & 0x04) == 0x04, 
                slv->pdelay);

        print_prefix();
        printf("|   ");
        printf("|         link's %d, active ports %d, ptype 0x%X\n",
                slv->link_cnt,
                slv->active_ports,
                slv->ptype);

        print_prefix();
        printf("|   ");
        printf("|         sync manager channel's %d, fmmu channel's %d\n", 
                slv->sm_ch,
                slv->fmmu_ch);      
        
        print_prefix();
        printf("|   ");
        printf("|         auto inc adr %d, fixed addr %d\n", 
                slv->auto_inc_address,
                slv->fixed_address);      
    }
    
    ret = ec_set_state(pec, EC_STATE_PREOP);

    ret = ec_set_state(pec, EC_STATE_SAFEOP);
}

int max_print_level = 0;

// only log level <= 10 
void no_verbose_log(ec_t *pec, int lvl, const char *format, ...) __attribute__(( format(printf, 3, 4)));
void no_verbose_log(ec_t *pec, int lvl, const char *format, ...) {
    if (lvl > max_print_level)
        return;

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
};

void mii_read(int fd, ec_t *pec, int slave, int phy) {
    int i;
    for (i = 0; i < 0x20; ++i) {
        uint16_t data = 0;
        ec_miiread(pec, slave, phy, i, &data);
#if LIBETHERCAT_BUILD_POSIX == 1
        int ret = write(fd, &data, sizeof(data));

        if (ret == -1) {
            perror("write returned:");
            break;
        }
#endif
    }
}

enum tool_mode {
    mode_undefined,
    mode_read,
    mode_write, 
    mode_test
};

ec_t ec;

int main(int argc, char **argv) {
    int ret, slave, i, phy = 0;
    int base_prio = 60;
    int base_affinity = 0x8;
    ec_t *pec = &ec;

    char *intf = NULL, *fn = NULL;
    int show_propagation_delays = 0;
    
    long reg = 0, val = 0;
    enum tool_mode mode = mode_undefined;
//    ec_log_func_user = NULL;
//    ec_log_func = &no_log;

    for (i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-i") == 0) ||
                (strcmp(argv[i], "--interface") == 0)) {
            if (++i < argc)
                intf = argv[i];
//        } else if ((strcmp(argv[i], "-p") == 0) ||
//                (strcmp(argv[i], "--propagation-delays") == 0)) {
//            show_propagation_delays = 1; 
        } else if ((strcmp(argv[i], "-r") == 0) ||
                (strcmp(argv[i], "--read") == 0)) {
            mode = mode_read; 
        } else if ((strcmp(argv[i], "-t") == 0) ||
                (strcmp(argv[i], "--test") == 0)) {
            mode = mode_test; 
        } else if ((strcmp(argv[i], "-w") == 0) ||
                (strcmp(argv[i], "--write") == 0)) {
            mode = mode_write; 
        } else if ((strcmp(argv[i], "-s") == 0) ||
                (strcmp(argv[i], "--slave") == 0)) {
            if (++i < argc)
                slave = atoi(argv[i]);
        } else if ((strcmp(argv[i], "-p") == 0) ||
                (strcmp(argv[i], "--phy-address") == 0)) {
            if (++i < argc)
                phy = atoi(argv[i]);
        } else if ((strcmp(argv[i], "-v") == 0) || 
                (strcmp(argv[i], "--verbose") == 0)) {
            max_print_level = 100;
        } else {
            // interpret as reg:value
            char *tmp = strstr(argv[i], ":");
            if (tmp) {
                char *regstr = strndup(argv[i], (int)(tmp-argv[i]));
                char *valstr = strndup(&tmp[1], (int)(strlen(argv[i]))-strlen(regstr)-1);
                printf("got reg %s, val %s\n", regstr, valstr);
                reg = strtol(regstr, NULL, 16);
                val = strtol(valstr, NULL, 16);
            } else 
                printf("command \"%s\" not understood\n", argv[i]);
        }
    }
    
    if ((argc == 1) || (intf == NULL))
        return usage(argc, argv);

    // use our log function
    pec->ec_log_func_user = NULL;
    pec->ec_log_func = &no_verbose_log;
    struct hw_common *phw = NULL;
            
#if LIBETHERCAT_BUILD_DEVICE_FILE == 1
    if ((intf[0] == '/') || (strncmp(intf, "file:", 5) == 0)) {
        // assume char device -> hw_file
        if (strncmp(intf, "file:", 5) == 0) {
            intf = &intf[5];
        }

        ec_log(10, "HW_OPEN", "Opening interface as device file: %s\n", intf);
        ret = hw_device_file_open(&hw_file, &ec, intf, base_prio - 1, base_affinity);

        if (ret == 0) {
            phw = &hw_file.common;
        }
    }
#endif
#if LIBETHERCAT_BUILD_DEVICE_BPF == 1
    if (strncmp(intf, "bpf:", 4) == 0) {
        intf = &intf[4];

        ec_log(10, "HW_OPEN", "Opening interface as BPF: %s\n", intf);
        ret = hw_device_bpf_open(&hw_bpf, intf);

        if (ret == 0) {
            phw = &hw_bpf.common;
        }
    }
#endif
#if LIBETHERCAT_BUILD_DEVICE_PIKEOS == 1
    if (strncmp(intf, "pikeos:", 7) == 0) {
        intf = &intf[7];

        ec_log(10, "HW_OPEN", "Opening interface as pikeos: %s\n", intf);
        ret = hw_device_pikeos_open(&hw_pikeos, intf, base_prio - 1, base_affinity);

        if (ret == 0) {
            phw = &hw_pikeos.common;
        }
    }
#endif
#if LIBETHERCAT_BUILD_DEVICE_SOCK_RAW_LEGACY == 1
    if (strncmp(intf, "sock-raw:", 9) == 0) {
        intf = &intf[9];
        
        ec_log(10, "HW_OPEN", "Opening interface as SOCK_RAW: %s\n", intf);
        ret = hw_device_sock_raw_open(&hw_sock_raw, &ec, intf, base_prio - 1, base_affinity);

        if (ret == 0) {
            phw = &hw_sock_raw.common;
        }
    }
#endif
#if LIBETHERCAT_BUILD_DEVICE_SOCK_RAW_MMAPED == 1
    if (strncmp(intf, "sock-raw-mmaped:", 16) == 0) {
        intf = &intf[16];

        ec_log(10, "HW_OPEN", "Opening interface as mmaped SOCK_RAW: %s\n", intf);
        ret = hw_device_sock_raw_mmaped_open(&hw_sock_raw_mmaped, &ec, intf, base_prio - 1, base_affinity);

        if (ret == 0) {
            phw = &hw_sock_raw_mmaped.common;
        }
    }
#endif

            
    ret = ec_open(&ec, phw, 1);


    if (show_propagation_delays)
        propagation_delays(&ec);

    int j, fd;
    
    if (mode == mode_read) {
        if (fn) {
#if LIBETHERCAT_BUILD_POSIX == 1
            fd = open(fn, O_CREAT | O_RDWR);
#endif
            mii_read(fd, &ec, slave, phy);
#if LIBETHERCAT_BUILD_POSIX == 1
            close(fd);
#endif
        } else
            mii_read(1, &ec, slave, phy);
    } else if (mode == mode_write) {
        uint16_t mii_value = val;
        ec_miiwrite(&ec, slave, phy, reg, &mii_value);
    } else if (mode == mode_test) {
        printf("now in test mode...\n");
        while (1) {
            uint16_t tmp, wkc;
            ec_brd(&ec, 0, &tmp, 2, &wkc);
        }
    }
        

    ec_close(&ec);

    return 0;
}

