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

#include <libethercat/config.h>
#include <libethercat/hw_sock_sotxtime.h>
#include <libethercat/ec.h>
#include <libethercat/idx.h>
#include <libethercat/error_codes.h>

#include <assert.h>

#ifdef LIBETHERCAT_HAVE_NET_IF_H
#    include <net/if.h>
#endif

#ifdef LIBETHERCAT_HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#endif

#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/errqueue.h>
#include <sys/mman.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/net_tstamp.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

// forward declarations
int  hw_device_sock_sotxtime_send(struct hw_common *phw, ec_frame_t *pframe, pooltype_t pool_type);
int  hw_device_sock_sotxtime_recv(struct hw_common *phw);
void hw_device_sock_sotxtime_send_finished(struct hw_common *phw);
int  hw_device_sock_sotxtime_get_tx_buffer(struct hw_common *phw, ec_frame_t **ppframe);
int  hw_device_sock_sotxtime_close(struct hw_common *phw);

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static void *hw_device_sock_sotxtime_rx_thread(void *arg);

// this need the grant_cap_net_raw kernel module
// see https://gitlab.com/fastflo/open_ethercat
#define GRANT_CAP_NET_RAW_PROCFS "/proc/grant_cap_net_raw"

static int try_grant_cap_net_raw_init(void) {
    int ret = 0;

    if (access(GRANT_CAP_NET_RAW_PROCFS, R_OK) != 0) {
        // does probably not exist or is not readable
    } else {
        int fd = open(GRANT_CAP_NET_RAW_PROCFS, O_RDONLY);
        if (fd == -1) {
            ec_log(1, "HW_OPEN", "error opening %s: %s\n", GRANT_CAP_NET_RAW_PROCFS, strerror(errno));
            ret = -1;
        } else {
            osal_char_t buffer[1024];
            int         n = read(fd, buffer, 1024);
            close(fd);
            if ((n <= 0) || (strncmp(buffer, "OK", 2) != 0)) {
                ret = -1;
            }
        }
    }

    return ret;
}

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
int hw_device_sock_sotxtime_open(
  struct hw_sock_sotxtime *phw_sock_raw, struct ec *pec, const osal_char_t *devname, int prio, int cpumask, int socket_priority, int clock_id) {
    int          ret = EC_OK;
    struct ifreq ifr;

    if (try_grant_cap_net_raw_init() == -1) {
        ec_log(10, "hw_open",
               "grant_cap_net_raw unsuccessfull, maybe we are "
               "not allowed to open a raw socket\n");
    }

    hw_open(&phw_sock_raw->common, pec);

    phw_sock_raw->common.send          = hw_device_sock_sotxtime_send;
    phw_sock_raw->common.recv          = hw_device_sock_sotxtime_recv;
    phw_sock_raw->common.send_finished = hw_device_sock_sotxtime_send_finished;
    phw_sock_raw->common.get_tx_buffer = hw_device_sock_sotxtime_get_tx_buffer;
    phw_sock_raw->common.close         = hw_device_sock_sotxtime_close;

    // create socket connection
    phw_sock_raw->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ECAT));
    if (phw_sock_raw->sockfd <= 0) {
        ec_log(1, "HW_OPEN", "socket error on opening SOCK_SOTXTIME_LOW: %s\n", strerror(errno));
        ret = EC_ERROR_UNAVAILABLE;
    }
    phw_sock_raw->sockfd_high = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ECAT));
    if (phw_sock_raw->sockfd_high <= 0) {
        ec_log(1, "HW_OPEN", "socket error on opening SOCK_SOTXTIME_HIGH: %s\n", strerror(errno));
        ret = EC_ERROR_UNAVAILABLE;
    }

    if (ret == EC_OK) {
        int i;

        // set timeouts
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 1;
        setsockopt(phw_sock_raw->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(phw_sock_raw->sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(phw_sock_raw->sockfd_high, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(phw_sock_raw->sockfd_high, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        struct ethtool_cmd cmd;
        cmd.cmd      = ETHTOOL_GSET;
        ifr.ifr_data = (void *)&cmd;
        (void)strncpy(ifr.ifr_name, devname, IFNAMSIZ);
        int err = ioctl(phw_sock_raw->sockfd_high, SIOCETHTOOL, &ifr);
        if (err != 0) {
            ec_log(1, "HW_OPEN", "Could not get speed: %s\n", strerror(errno));
            phw_sock_raw->if_speed = 0;
        } else {
            phw_sock_raw->if_speed = ethtool_cmd_speed(&cmd);
        }


        // do not route our frames
        i = 1;
        setsockopt(phw_sock_raw->sockfd, SOL_SOCKET, SO_DONTROUTE, &i, sizeof(i));
        setsockopt(phw_sock_raw->sockfd_high, SOL_SOCKET, SO_DONTROUTE, &i, sizeof(i));

        // Set priority and SO_TXTIME only for our rt traffic
        if (setsockopt(phw_sock_raw->sockfd_high, SOL_SOCKET, SO_PRIORITY, &socket_priority, sizeof(socket_priority)) < 0) {
            ec_log(1, "HW_OPEN", "Could not set priority to %d: %s\n", socket_priority, strerror(errno));
        }
        struct sock_txtime sotxtime = {.clockid = clock_id, .flags = (SOF_TXTIME_REPORT_ERRORS)};
        if (setsockopt(phw_sock_raw->sockfd_high, SOL_SOCKET, SO_TXTIME, &sotxtime, sizeof(sotxtime)) < 0) {
            ec_log(1, "HW_OPEN", "Could not set SO_TXTIME: %s\n", strerror(errno));
        }

        // Get ifindex

        err = ioctl(phw_sock_raw->sockfd_high, SIOCGIFINDEX, &ifr);
        if (err < 0) {
            ec_log(1, "HW_OPEN", "Could not get IFINDEX: %s", strerror(errno));
            ret = EC_ERROR_UNAVAILABLE;
            return ret;
        }
        phw_sock_raw->ifindex = ifr.ifr_ifindex;

        // attach to out network interface
        (void)strcpy(ifr.ifr_name, devname);
        ifr.ifr_flags = 0;
        ioctl(phw_sock_raw->sockfd_high, SIOCGIFFLAGS, &ifr);
        ioctl(phw_sock_raw->sockfd, SIOCGIFFLAGS, &ifr);


        osal_bool_t iff_running = (ifr.ifr_flags & IFF_RUNNING) == 0 ? OSAL_FALSE : OSAL_TRUE;
        ifr.ifr_flags           = ifr.ifr_flags | IFF_PROMISC | IFF_BROADCAST | IFF_UP;
        ioctl(phw_sock_raw->sockfd_high, SIOCSIFFLAGS, &ifr);
        ioctl(phw_sock_raw->sockfd, SIOCSIFFLAGS, &ifr);


        osal_timer_t up_timeout;
        osal_timer_init(&up_timeout, 10000000000);
        while (iff_running == OSAL_FALSE) {
            ioctl(phw_sock_raw->sockfd, SIOCGIFFLAGS, &ifr);
            osal_bool_t isrunning_raw = (ifr.ifr_flags & IFF_RUNNING) == 0 ? OSAL_FALSE : OSAL_TRUE;
            ioctl(phw_sock_raw->sockfd_high, SIOCGIFFLAGS, &ifr);
            osal_bool_t isrunning_sotxtime = (ifr.ifr_flags & IFF_RUNNING) == 0 ? OSAL_FALSE : OSAL_TRUE;
            iff_running                    = isrunning_raw && isrunning_sotxtime;
            if (iff_running == OSAL_TRUE) {
                ec_log(10, "HW_OPEN", "interface %s is RUNNING now, wait additional 2 sec for link to be established!\n", devname);
                osal_sleep(1000000000);
            } else {
                ec_log(10, "HW_OPEN", "interface %s is not RUNNING, waiting ...\n", devname);
            }

            if (osal_timer_expired(&up_timeout) == OSAL_ERR_TIMEOUT) {
                break;
            }

            osal_sleep(1000000000);
        }

        if (iff_running == OSAL_FALSE) {
            ec_log(1, "HW_OPEN", "unable to bring interface %s UP!\n", devname);
            ret = EC_ERROR_UNAVAILABLE;
            close(phw_sock_raw->sockfd);
            close(phw_sock_raw->sockfd_high);
            phw_sock_raw->sockfd      = 0;
            phw_sock_raw->sockfd_high = 0;
        }
    }

    if (ret == EC_OK) {
        ec_log(10, "HW_OPEN", "binding sotxtime socket to %s\n", devname);

        (void)memset(&ifr, 0, sizeof(ifr));
        (void)strncpy(ifr.ifr_name, devname, IFNAMSIZ);
        ioctl(phw_sock_raw->sockfd, SIOCGIFMTU, &ifr);
        phw_sock_raw->common.mtu_size = ifr.ifr_mtu;
        ec_log(10, "HW_OPEN", "got mtu size %d\n", phw_sock_raw->common.mtu_size);

        // bind socket to protocol, in this case RAW EtherCAT */
        struct sockaddr_ll sll;
        (void)memset(&sll, 0, sizeof(sll));
        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = phw_sock_raw->ifindex;
        sll.sll_protocol = htons(ETH_P_ECAT);
        int err          = bind(phw_sock_raw->sockfd, (struct sockaddr *)&sll, sizeof(sll));
        if (err != 0) {
            ec_log(1, "HW_OPEN", "Could not bind: %s\n", strerror(errno));
            ret = EC_ERROR_UNAVAILABLE;
            close(phw_sock_raw->sockfd);
            close(phw_sock_raw->sockfd_high);
        }
    }

    if (ret == EC_OK) {
        phw_sock_raw->rxthreadrunning = 1;
        osal_task_attr_t attr;
        attr.policy   = OSAL_SCHED_POLICY_FIFO;
        attr.priority = prio;
        attr.affinity = cpumask;
        (void)strcpy(&attr.task_name[0], "ecat.rx");
        osal_task_create(&phw_sock_raw->rxthread, &attr, hw_device_sock_sotxtime_rx_thread, phw_sock_raw);
    }

    return ret;
}

//! Close hardware layer
/*!
 * \param[in]   phw         Pointer to hw handle.
 *
 * \return 0 or negative error code
 */
int hw_device_sock_sotxtime_close(struct hw_common *phw) {
    int ret = 0;

    struct hw_sock_sotxtime *phw_sock_sotxtime = container_of(phw, struct hw_sock_sotxtime, common);

    phw_sock_sotxtime->rxthreadrunning = 0;
    osal_task_join(&phw_sock_sotxtime->rxthread, NULL);

    close(phw_sock_sotxtime->sockfd);
    close(phw_sock_sotxtime->sockfd_high);

    return ret;
}

//! Receive a frame from an EtherCAT hw device.
/*!
 * \param[in]   phw         Pointer to hw handle. 
 *
 * \return 0 or negative error code
 */
int hw_device_sock_sotxtime_recv(struct hw_common *phw) {
    assert(phw != NULL);

    // cppcheck-suppress misra-c2012-11.3
    struct hw_sock_sotxtime *phw_sock_sotxtime = container_of(phw, struct hw_sock_sotxtime, common);
    ec_frame_t              *pframe            = (ec_frame_t *)&phw_sock_sotxtime->recv_frame;

    // using tradional recv function
    osal_ssize_t bytesrx = recv(phw_sock_sotxtime->sockfd, pframe, ETH_FRAME_LEN, 0);

    if (bytesrx > 0) {
        hw_process_rx_frame(phw, pframe);
    }

    return EC_OK;
}

//! receiver thread
void *hw_device_sock_sotxtime_rx_thread(void *arg) {
    // cppcheck-suppress misra-c2012-11.5
    struct hw_sock_sotxtime *phw_sock_raw = (struct hw_sock_sotxtime *)arg;

    assert(phw_sock_raw != NULL);

    osal_task_sched_priority_t rx_prio;
    if (osal_task_get_priority(&phw_sock_raw->rxthread, &rx_prio) != OSAL_OK) {
        rx_prio = 0;
    }

    ec_log(10, "HW_SOCK_RAW_RX", "receive thread running (prio %d)\n", rx_prio);

    while (phw_sock_raw->rxthreadrunning != 0) {
        (void)hw_device_sock_sotxtime_recv(&phw_sock_raw->common);
    }

    ec_log(10, "HW_SOCK_RAW_RX", "receive thread stopped\n");

    return NULL;
}

//! Get a free tx buffer from underlying hw device.
/*!
 * \param[in]   phw         Pointer to hw handle. 
 * \param[in]   ppframe     Pointer to return frame buffer pointer.
 *
 * \return 0 or negative error code
 */
int hw_device_sock_sotxtime_get_tx_buffer(struct hw_common *phw, ec_frame_t **ppframe) {
    assert(phw != NULL);
    assert(ppframe != NULL);

    int                      ret          = EC_OK;
    ec_frame_t              *pframe       = NULL;
    struct hw_sock_sotxtime *phw_sock_raw = container_of(phw, struct hw_sock_sotxtime, common);

    static const osal_uint8_t mac_dest[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const osal_uint8_t mac_src[]  = {0x00, 0x30, 0x64, 0x0f, 0x83, 0x35};

    // cppcheck-suppress misra-c2012-11.3
    pframe = (ec_frame_t *)phw_sock_raw->send_frame;

    // reset length to send new frame
    (void)memcpy(pframe->mac_dest, mac_dest, 6);
    (void)memcpy(pframe->mac_src, mac_src, 6);
    pframe->ethertype = htons(ETH_P_ECAT);
    pframe->type      = 0x01;
    pframe->len       = sizeof(ec_frame_t);

    *ppframe = pframe;

    return ret;
}

//! Get a free tx buffer from underlying hw device.
/*!
 * \param[in]   fd        socket handle. 
 *
 * \return 0 or negative error code
 */
static int process_socket_error_queue(int fd) {
    static unsigned char      tx_buffer[256];
    uint8_t                   msg_control[CMSG_SPACE(sizeof(struct sock_extended_err))];
    unsigned char             err_buffer[sizeof(tx_buffer)];
    struct sock_extended_err *serr;
    struct cmsghdr           *cmsg;
    __u64                     tstamp = 0;

    struct iovec  iov = {.iov_base = err_buffer, .iov_len = sizeof(err_buffer)};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = msg_control, .msg_controllen = sizeof(msg_control)};

    if (recvmsg(fd, &msg, MSG_ERRQUEUE) == -1) {
        ec_log(1, "HW_TX", "recvmsg failed\n");
        return -1;
    }

    cmsg = CMSG_FIRSTHDR(&msg);
    while (cmsg != NULL) {
        serr = (void *)CMSG_DATA(cmsg);
        if (serr->ee_origin == SO_EE_ORIGIN_TXTIME) {
            tstamp = ((__u64)serr->ee_data << 32) + serr->ee_info;

            switch (serr->ee_code) {
                case SO_EE_CODE_TXTIME_INVALID_PARAM:
                    ec_log(1, "HW_TX", "packet with tstamp %llu dropped due to invalid params\n", tstamp);
                    return 0;
                case SO_EE_CODE_TXTIME_MISSED:
                    ec_log(1, "HW_TX", "packet with tstamp %llu dropped due to missed deadline\n", tstamp);
                    return 0;
                default:
                    return -1;
            }
        }

        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    return 0;
}

//! Send a frame from an EtherCAT hw device.
/*!
 * \param[in]   phw         Pointer to hw handle. 
 * \param[in]   pframe      Pointer to frame buffer.
 * \param[in]   pool_type   Pool type to distinguish between high and low prio frames.
 *
 * \return 0 or negative error code
 */
int sock_raw_send(struct hw_common *phw, ec_frame_t *pframe) {
    assert(phw != NULL);
    assert(pframe != NULL);


    int ret = EC_OK;

    struct hw_sock_sotxtime *phw_sock_raw = container_of(phw, struct hw_sock_sotxtime, common);

    // no more datagrams need to be sent or no more space in frame
    osal_ssize_t bytestx = send(phw_sock_raw->sockfd, pframe, pframe->len, 0);

    if ((osal_ssize_t)pframe->len != bytestx) {
        ec_log(1, "HW_TX",
               "rawsend - got only %" PRId64
               " bytes out of %d bytes "
               "through.\n",
               bytestx, pframe->len);

        if (bytestx == -1) {
            ec_log(1, "HW_TX", "error: %s\n", strerror(errno));
        }

        ret = EC_ERROR_HW_SEND;
    }

    return ret;
}

//! Calculates the transmission time based on the link speed in nano seconds
static inline uint64_t frame_transmission_time(size_t frame_len, int iface_speed) {

    const uint64_t inter_frame_gap_bit = 96;
    uint64_t       bittime_ns          = 1000ull / (uint64_t)iface_speed;
    return (MIN(frame_len, 64) * 8 + inter_frame_gap_bit) * bittime_ns;
}

int sotxtime_send(struct hw_common *phw, ec_frame_t *pframe) {
    assert(phw != NULL);
    assert(pframe != NULL);

    struct hw_sock_sotxtime *phw_sock_raw = container_of(phw, struct hw_sock_sotxtime, common);
    int                      ret          = EC_OK;
    char                     control[CMSG_SPACE(sizeof(uint64_t))];
    struct msghdr            msg = {0};
    struct iovec             iov = {0};
    struct cmsghdr          *cm;
    uint64_t                 tdeliver;

    // Construct address for sendmsg.
    struct sockaddr_ll dst_address;
    memset(&dst_address, 0, sizeof(dst_address));
    dst_address.sll_ifindex = phw_sock_raw->ifindex;
    dst_address.sll_halen   = ETH_ALEN;
    for (int i = 0; i < 6; i++) {
        dst_address.sll_addr[i] = pframe->mac_dest[i];
    }
    dst_address.sll_family   = AF_PACKET;
    dst_address.sll_protocol = htons(ETH_P_ECAT);

    iov.iov_base = pframe;
    iov.iov_len  = pframe->len;

    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    msg.msg_name    = (struct sockaddr *)&dst_address;
    msg.msg_namelen = sizeof(struct sockaddr_ll);


    memset(control, 0, sizeof(control));
    msg.msg_control    = &control;
    msg.msg_controllen = sizeof(control);

    tdeliver            = phw_sock_raw->next_txtime;
    // If more than one packet is sent in one cycle we place them sequencaly.
    // Therefore we have to calculate the next free time.
    const size_t buffer = 20;
    phw_sock_raw->next_txtime += frame_transmission_time(pframe->len, phw_sock_raw->if_speed) + buffer;

    cm             = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type  = SCM_TXTIME;
    cm->cmsg_len   = CMSG_LEN(sizeof(tdeliver));
    memcpy(CMSG_DATA(cm), &tdeliver, sizeof(tdeliver));

    // no more datagrams need to be sent or no more space in frame
    osal_ssize_t bytestx = sendmsg(phw_sock_raw->sockfd_high, &msg, 0);


    if ((osal_ssize_t)pframe->len != bytestx) {
        ec_log(1, "HW_TX",
               "sotxtime send - got only %ld bytes out of %d bytes "
               "through.\n",
               bytestx, pframe->len);

        if (bytestx == -1) {
            ec_log(1, "HW_TX", "error: %s\n", strerror(errno));
        }

        ret = EC_ERROR_HW_SEND;
    }

    return ret;
}


//! Send a frame from an EtherCAT hw device.
/*!
 * \param[in]   phw         Pointer to hw handle. 
 * \param[in]   pframe      Pointer to frame buffer.
 * \param[in]   pool_type   Pool type to distinguish between high and low prio frames.
 *
 * \return 0 or negative error code
 */
int hw_device_sock_sotxtime_send(struct hw_common *phw, ec_frame_t *pframe, pooltype_t pool_type) {
    assert(phw != NULL);
    assert(pframe != NULL);


    if (pool_type == POOL_HIGH) {
        return sotxtime_send(phw, pframe);
    } else {
        return sock_raw_send(phw, pframe);
    }
}

//! Doing internal stuff when finished sending frames
/*!
 * \param[in]   phw         Pointer to hw handle.
 */
void hw_device_sock_sotxtime_send_finished(struct hw_common *phw) {}

//! set txtime time stamp for the tx high queue. The timestamp must be calculated
//! in the user application in connection with the application scheduling
/*!
 * \param phw hardware handle
 * \param next_txtime next txtime
 * \return 0 or error code
 */
int hw_high_set_next_txtime(struct hw_sock_sotxtime *phw, osal_int64_t next_txtime) {
    assert(phw != NULL);
    int ret = EC_OK;

    phw->next_txtime = next_txtime;

    return ret;
}