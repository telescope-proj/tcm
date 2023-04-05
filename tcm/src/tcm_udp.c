#include "tcm_udp.h"
#include "tcm_comm.h"
#include "tcm_log.h"

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