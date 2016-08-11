
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("Connecting site : %s\n", (char *)data);
    FILE *mal = fopen("mal_site.txt", "r");
    char *site;
    int buf_size=1024;
    site=malloc(buf_size+1);
    char addr[200];
    char *malsite[200];
    int i=0, j=0;
    strcpy(addr, (char *)data);

    while(fgets(site, buf_size, mal)){
        malsite[i]=malloc(strlen(site)+1);
        strcpy(malsite[i], site+strlen("http://"));
        if(strstr(malsite[i], "www.") != NULL){
            strcpy(malsite[i], malsite[i]+strlen("www."));
        }
        int idx=strlen(malsite[i]);
        malsite[i][idx-1]='\0';
        for(idx=0; idx<strlen(malsite[i]); idx++){
            if(malsite[i][idx]=='/' && malsite[i][idx+1]=='\0'){
                malsite[i][idx]='\0';
                break;
            }
        }
        if(strstr(addr, malsite[i]) != NULL){
            printf("Found!!\n");
            return 0;
        }
        i++;
    }

    for(j=0; j<i; j++)
        free(malsite[j]);

    fclose(mal);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void dump(unsigned char* buf, size_t len, char *address) {
    size_t i;
    unsigned char *test=buf;

    char phttp[5];
    for(i=0; i<len; i++){
        if(*test=='H'){
            strncpy(phttp, (char *)test, 4);
            phttp[4]='\0';
            if(!strcmp(phttp, "HTTP")){
                break;
            }
        }
        test++;
    }

    if(i==len){
        strcpy(address, "Nothing");
        return;
    }

    test=buf;
    char pget[4];
    for(i=0; i<len; i++){
        if(*test=='G'){
            strncpy(pget, (char *)test, 3);
            pget[3]='\0';
            if(!strcmp(pget, "GET")){
                break;
            }
        }
        test++;
    }
    unsigned char *findget=test+strlen("GET ");

    test=buf;
    char phost[6];
    for(i=0; i<len; i++){
        if(*test=='H'){
            strncpy(phost, (char *)test, 5);
            phost[5]='\0';
            if(!strcmp(phost, "Host:")){
                break;
            }
        }
        test++;
    }
    unsigned char *findhost=test+strlen("Host: ");

    int idx=0;
    while(*findhost!='\r'){
        address[idx++]=*findhost++;
    }

    while(*findget!=' '){
        address[idx++]=*findget++;
    }
    address[idx]='\0';
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    char addr[200];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, (void *)&addr);   // Adding variable addr
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            dump(buf, rv, addr);
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
     * are sent from kernel-space, the socket buffer that we use
     * to enqueue packets may fill up returning ENOBUFS. Depending
     * on your application, this error may be ignored. Please, see
     * the doxygen documentation of this library on how to improve
     * this situation.
     */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
