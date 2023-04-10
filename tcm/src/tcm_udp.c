#include "tcm_udp.h"
#include "tcm_comm.h"
#include "tcm_log.h"

int tcm_setup_udp(struct sockaddr * sa, tcm_sock_mode mode, tcm_sock * sock_out)
{
    int sa_size = tcm__get_sa_size(sa);
    if (sa_size < 0)
    {
        return sa_size;
    }

    tcm_sock sock = socket(sa->sa_family, 
                           SOCK_DGRAM | 
                           (mode == TCM_SOCK_MODE_ASYNC ? SOCK_NONBLOCK : 0),
                           0);
    if (!tcm_sock_valid(sock))
    {
        tcm__log_error("UDP socket creation failed: %s", strerror(tcm_sock_err));
        return -tcm_sock_err;
    }

    int ret = bind(sock, sa, sa_size);
    if (ret < 0)
    {
        tcm__log_error("Socket bind failed: %s", strerror(tcm_sock_err));
        close(sock);
        return -tcm_sock_err;
    }

    * sock_out = sock;
    return 0;
}


ssize_t tcm_send_udp(tcm_sock sock, void * buf, uint64_t buf_size,
                     struct sockaddr * peer, tcm_time * timing)
{
    int ret, flag = 0;
    socklen_t size = tcm__get_sa_size(peer);
    if (size < 0)
    {
        return size;
    }
    
    if (timing->ts.tv_sec == 0 && timing->ts.tv_nsec == 0)
    {
        ret = sendto(sock, buf, buf_size, 0, peer, size);
        if (ret < 0)
            return -tcm_sock_err;
        else
            return ret;
    }
    else
    {   
        struct timespec dl;
        ret = tcm_conv_time(timing, &dl);
        if (ret < 0)
            return ret;

        while (!tcm_check_deadline(&dl))
        {
            ret = sendto(sock, buf, buf_size, 0, peer, size);
            if (ret < 0)
            {
                if (tcm_sock_err == EAGAIN || tcm_sock_err == EWOULDBLOCK)
                {
                    tcm_sleep(timing->interval);
                    continue;
                }
                tcm__log_error( "Failed to send message: %s", 
                                strerror(tcm_sock_err));
                return -tcm_sock_err;
            }
            flag = 1;
            break;
        }
    }

    if (flag == 0)
        return -ETIMEDOUT;

    return ret;
}

ssize_t tcm_recv_udp(tcm_sock sock, void * buf, uint64_t buf_size,
                     struct sockaddr * peer, tcm_time * timing)
{
    int ret, flag = 0;
    socklen_t size = tcm__get_sa_size(peer);
    if (size < 0)
    {
        return size;
    }
    
    if (timing->ts.tv_sec == 0 && timing->ts.tv_nsec == 0)
    {
        ret = sendto(sock, buf, buf_size, 0, peer, size);
        if (ret < 0)
            return -tcm_sock_err;
        else
            return ret;
    }
    else
    {   
        struct timespec dl;
        ret = tcm_conv_time(timing, &dl);
        if (ret < 0)
            return ret;

        while (!tcm_check_deadline(&dl))
        {
            ret = recvfrom(sock, buf, buf_size, 0, peer, &size);
            if (ret < 0)
            {
                if (tcm_sock_err == EAGAIN || tcm_sock_err == EWOULDBLOCK)
                {
                    tcm_sleep(timing->interval);
                    continue;
                }
                tcm__log_error( "Failed to recv message: %s", 
                                strerror(tcm_sock_err));
                return -tcm_sock_err;
            }
            flag = 1;
            break;
        }
    }

    if (flag == 0)
        return -ETIMEDOUT;

    return ret;
}


ssize_t tcm_exch_udp(tcm_sock sock, void * send_buf, uint64_t send_buf_size,
                     void * recv_buf, uint64_t recv_buf_size,
                     struct sockaddr * peer, tcm_time * timing)
{
    ssize_t ret;
    tcm_time timer;
    timer.interval  = timing->interval;
    timer.delta     = 0;
    ret = tcm_conv_time(timing, &timer.ts);
    if (ret < 0)
    {
        return ret;
    }
    ret = tcm_send_udp(sock, send_buf, send_buf_size, peer, &timer);
    if (ret < 0)
    {
        return ret;
    }
    ret = tcm_recv_udp(sock, recv_buf, recv_buf_size, peer, &timer);
    return ret;
}

int tcm_set_timeout_udp(tcm_sock sock, size_t send_ms, size_t recv_ms)
{
    int ret;
    struct timeval rto, sto;
    rto.tv_sec  = recv_ms / 1000;
    rto.tv_usec = (recv_ms % 1000) * 1000;
    sto.tv_sec  = send_ms / 1000;
    sto.tv_usec = (send_ms % 1000) * 1000;

    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
    if (ret < 0)
        return -errno;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto) < 0);
    if (ret < 0)
        return -errno;
    return 0;
}