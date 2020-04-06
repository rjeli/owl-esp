#include <string.h>
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "driver/gpio.h"

#include "../src/state.h"
#include "../src/rx.h"
#include "../src/tx.h"
#include "../src/log.h"
#include "../src/schedule.h"

#include "owl.h"

// led util
#define LED_PIN 2
static inline void led_on() { gpio_set_level(LED_PIN, 1); }
static inline void led_off() { gpio_set_level(LED_PIN, 0); }
static void led_clearer(void *arg) { led_off(); }
static void led_init() { 
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT); 
    esp_timer_create_args_t targs = {
        .callback = led_clearer,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "led_clearer",
    };
    esp_timer_handle_t h;
    ESP_ERROR_CHECK(esp_timer_create(&targs, &h));
    ESP_ERROR_CHECK(esp_timer_start_periodic(h, 10*1000));
}

// globals

struct owl_state {
    struct awdl_state awdl_state;
    struct ieee80211_state ieee80211_state;
    uint8_t *next_ping_buf;
    int next_ping_len;
};
struct owl_state *OWL_STATE = NULL;

// fns

int
owl_addone(int x)
{
    return x + 1;
}

static char ETHER_NTOA_BUF[32];

char *
ether_ntoa(const struct ether_addr *addr)
{
    const uint8_t *b = &addr->ether_addr_octet[0];
    sprintf(ETHER_NTOA_BUF, "%02x:%02x:%02x:%02x:%02x:%02x",
        b[0], b[1], b[2], b[3], b[4], b[5]);
    return ETHER_NTOA_BUF;
}

static void
wifi_rx_cb(void *_pkt, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = _pkt;

	uint64_t tsft = clock_time_us();

    if (pkt->payload[0] == 0x08) {
        if (!memcmp(&pkt->payload[16], "\x00\x25\x00\xff\x94\x73", 6)) {
            printf("got awdl_data pkt for %s\n", 
                ether_ntoa((struct ether_addr *) &pkt->payload[4]));
            if (!memcmp(&pkt->payload[4], "\x01\x02\x03\x04\x05\x06", 6)) {
                for (int i = 0; i < 100; i++) {
                    printf("I GOT A DATA PACKET!\n");
                }
            }
            if (!memcmp(&pkt->payload[4], "\x33\x33\x00\x00\x00\x01", 6)) {
                if (pkt->payload[46] == 0x3a && pkt->payload[80] == 0x80) {
                    printf("it's a ping request!\n");
                    if (!OWL_STATE->next_ping_len) {
                        int ping_len = pkt->rx_ctrl.sig_len - 40;
                        OWL_STATE->next_ping_len = ping_len;
                        memcpy(OWL_STATE->next_ping_buf, &pkt->payload[40], ping_len);
                    }
                } else {
                    printf("its not a ping request? %02x %02x\n", 
                        pkt->payload[46], pkt->payload[80]);
                }
            }
        }
        return;
    }

    if (pkt->payload[0] != 0xd0) return; // only MGMT-ACTION frame

    led_on();
    printf("got action frame\n");

	const struct buf *frame = buf_new_const(pkt->payload, pkt->rx_ctrl.sig_len);

    // check length
	READ_BYTES(frame, 0, NULL, sizeof(struct ieee80211_hdr));

	struct ieee80211_hdr *wlan_hdr = (struct ieee80211_hdr *) buf_data(frame);
    struct ether_addr *from = &wlan_hdr->addr2, *to = &wlan_hdr->addr1;

	BUF_STRIP(frame, sizeof(struct ieee80211_hdr));

    // strip checksum
    BUF_TAKE(frame, 4);

	int ret = awdl_rx_action(frame, 
        pkt->rx_ctrl.rssi, tsft, from, to, &OWL_STATE->awdl_state);
    if (ret != RX_OK) {
        printf("bad rx_action: %d\n", ret);
        return;
    }

    printf("it went ok?\n");
    return;

wire_error:
    printf("wire err!\n");
}

static void
print_netifs()
{
    size_t nr_ifs = esp_netif_get_nr_of_ifs();
    esp_netif_t *netif = NULL;
    for (unsigned int i = 0; i < nr_ifs; i++) {
        netif = esp_netif_next(netif);
        printf("if %d key: %s type: %s\n", i, 
            esp_netif_get_ifkey(netif), esp_netif_get_desc(netif));
    }
}

static void 
owl_awdl_neighbor_add(struct awdl_peer *p, void *arg) {
	// struct io_state *io_state = _io_state;
	// neighbor_add_rfc4291(io_state->host_ifindex, &p->addr);
    printf("owl_awdl_neighbor_add\n");
}

static void 
owl_awdl_neighbor_remove(struct awdl_peer *p, void *arg) {
	// struct io_state *io_state = _io_state;
	// neighbor_remove_rfc4291(io_state->host_ifindex, &p->addr);
    printf("owl_awdl_neighbor_remove\n");
}

static void
print_stats_task(void *arg)
{
    struct awdl_stats *stats = &OWL_STATE->awdl_state.stats;
    awdl_peers_t peers = OWL_STATE->awdl_state.peers.peers;
    char *peer_print_buf = malloc(4096);
    for (;;) {
        printf("=== STATS ===\n");
	    printf(" TX action %llu, data %llu, unicast %llu, multicast %llu\n",
	        stats->tx_action, stats->tx_data, 
            stats->tx_data_unicast, stats->tx_data_multicast);
	    printf(" RX action %llu, data %llu, unknown %llu\n",
	        stats->rx_action, stats->rx_data, stats->rx_unknown);
        printf("=== PEERS ===\n");
        int len = awdl_peers_print(peers, peer_print_buf, 4096);
        peer_print_buf[len] = '\0';
        printf("%s\n", peer_print_buf);
        vTaskDelay(5000/portTICK_RATE_MS);
    }
}

struct timer_ctx {
    esp_timer_handle_t h;
};

static esp_timer_handle_t
make_timer(const char *name, esp_timer_cb_t cb)
{
    struct timer_ctx *ctx = malloc(sizeof(*ctx));
    esp_timer_create_args_t tcfg = {
        .callback = cb,
        .arg = ctx,
        .dispatch_method = ESP_TIMER_TASK,
        .name = name,
    };
    esp_timer_handle_t h;
    ESP_ERROR_CHECK(esp_timer_create(&tcfg, &h));
    ctx->h = h;
    return h;
}

#define RUN_PERIODIC(cb, us) \
    ESP_ERROR_CHECK(esp_timer_start_periodic(make_timer(#cb, cb), (us)))
#define RUN_ONESHOT(cb, us) \
    ESP_ERROR_CHECK(esp_timer_start_once(make_timer(#cb, cb), (us)))
#define REARM_ONESHOT(ctx, us) \
    ESP_ERROR_CHECK(esp_timer_start_once((ctx)->h, (us)))

static void
send_action(enum awdl_action_type type)
{
    uint8_t *buf = malloc(4096);
	int len = awdl_init_full_action_frame(buf, 
        &OWL_STATE->awdl_state, &OWL_STATE->ieee80211_state, type);
	log_trace("send %s len %d", awdl_frame_as_str(type), len);
    ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false));
    free(buf);
}

static void
send_psf(void *_ctx)
{
    (void) _ctx;
	send_action(AWDL_ACTION_PSF);
}

static void
send_mif(void *_ctx)
{
    struct timer_ctx *ctx = _ctx;
    struct awdl_state *awdl_state = &OWL_STATE->awdl_state;

	/* send MIF in middle of sequence (if non-zero) */
	if (awdl_chan_num(awdl_state->channel.current, awdl_state->channel.enc) > 0) {
		send_action(AWDL_ACTION_MIF);
    }

	uint64_t now = clock_time_us();
	uint64_t next_aw = awdl_sync_next_aw_us(now, &awdl_state->sync);
	uint64_t eaw_len = awdl_state->sync.presence_mode * awdl_state->sync.aw_period;

	/* schedule next in the middle of EAW */
    REARM_ONESHOT(ctx, next_aw + (eaw_len/2)*1024);
}

uint8_t ping_pkt[] = {
    0x60, 0x03, 0x0c, 0xde, // ipv6 hdr
    0x00, 0x10, // payload len 16
    0x3a, // icmpv6
    0x40, // hop limit 64
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src
    0x03, 0x02, 0x03, 0xff, 0xfe, 0x04, 0x05, 0x06,
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

    0x80, // ping request
    0x00, // code
    0xfc, 0x27, // checksum
    0x58, 0xa1, // identifier
    0x00, 0x00, // seqnum
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // data??
};

static void
send_ping(void *_ctx)
{
    struct timer_ctx *ctx = _ctx;
    struct awdl_state *awdl_state = &OWL_STATE->awdl_state;

    uint64_t now = clock_time_us();
	double in = awdl_can_send_in(awdl_state, now, AWDL_MULTICAST_GUARD_TU);
    printf("in: %f\n", in);
	if (awdl_is_multicast_eaw(awdl_state, now) && (in == 0)) {
        /* we can send now */
        struct ether_addr src = {{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }};
        struct ether_addr dst = {{ 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 }};
        uint8_t *buf = malloc(4096);
        int len = awdl_init_full_data_frame(
            buf, &src, &dst,
            ping_pkt, sizeof(ping_pkt),
            awdl_state, &OWL_STATE->ieee80211_state);
        uint64_t now = clock_time_us();
        uint16_t period = 
            awdl_sync_current_eaw(now, &awdl_state->sync) / AWDL_CHANSEQ_LENGTH;
        uint16_t slot = 
            awdl_sync_current_eaw(now, &awdl_state->sync) % AWDL_CHANSEQ_LENGTH;
        uint16_t tu = awdl_sync_next_aw_tu(now, &awdl_state->sync);
        log_debug("send data (len %d) to %s (%u.%u.%u)", len,
                  ether_ntoa(&dst), period, slot, tu);
        ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false));
        free(buf);
        awdl_state->stats.tx_data++;
    } else {
		if (in == 0) {
            /* try again next EAW */
		    in = 64*1024/1000.0/1000.0;
        } else if (in < 0) {
            /* we are at the end of slot but within guard */
			in = -in + (AWDL_MULTICAST_GUARD_TU*1024)/1000.0/1000.0;
        }
    }

    printf("retrying ping in %f ms\n", (in*1000));
    REARM_ONESHOT(ctx, in*1000.0*1000.0);
}

static void
print_ip6(uint8_t *b)
{
    for (int i = 0; i < 16; i++) {
        if (i > 0 && i % 2 == 0) {
            printf(":");
        }
        printf("%02x", b[i]);
    }
}

static void
send_unicast(void *_ctx)
{
    struct timer_ctx *ctx = _ctx;
    struct awdl_state *awdl_state = &OWL_STATE->awdl_state;
	uint64_t now = clock_time_us();
    double in = 0;

    if (OWL_STATE->next_ping_len) {
        uint8_t *ip6_src = &OWL_STATE->next_ping_buf[8];
        uint8_t *ip6_dst = &OWL_STATE->next_ping_buf[24];
        printf("got a ping from ");
        print_ip6(ip6_src);
        printf(" to ");
        print_ip6(ip6_dst);
        printf("\n");

        struct ether_addr eth_src = {{
            ip6_src[8]^0x2,
            ip6_src[9],
            ip6_src[10],
            ip6_src[13],
            ip6_src[14],
            ip6_src[15],
        }};

        printf("src mac: %s\n", ether_ntoa(&eth_src));

		struct awdl_peer *peer;
        if (awdl_peer_get(awdl_state->peers.peers, &eth_src, &peer) < 0) {
            printf("no peer found\n");
        } else {
            printf("yes peer found\n");
			in = awdl_can_send_unicast_in(awdl_state, peer, now, AWDL_UNICAST_GUARD_TU);
			// if (in == 0) { 
            if (in < 0.05) { // within 100ms?
                /* send now */
                printf("sending now\n");

				// awdl_send_data(state->next, &state->io, 
                //     &state->awdl_state, &state->ieee80211_state);
				// buf_free(state->next);
				// state->next = NULL;
				// state->awdl_state.stats.tx_data_unicast++;

                // set ipv6 dst to original src
                memcpy(ip6_dst, ip6_src, 16);
                // set ipv6 src to my addr
                uint8_t my_ip6[] = {
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xe0, 0xca, 0xfe, 0xff, 0xfe, 0xba, 0xbe, 0xba,
                };
                memcpy(ip6_src, my_ip6, 16);
                // set eth src to my addr
                struct ether_addr my_eth = {{ 0xe2, 0xca, 0xfe, 0xba, 0xbe, 0xba }};
                // set icmpv6 type to REPLY
                OWL_STATE->next_ping_buf[40] = 0x81;

                uint8_t *buf = malloc(4096);
                int len = awdl_init_full_data_frame(
                    buf, &my_eth, &eth_src,
                    OWL_STATE->next_ping_buf, OWL_STATE->next_ping_len,
                    awdl_state, &OWL_STATE->ieee80211_state);
                ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, buf, len, false));
                free(buf);

                // OWL_STATE->next_ping_len = 0;
                in += 0.5;
			} else { 
                printf("trying to send in %f\n", in);
                /* try later */
				if (in < 0) {
                    /* we are at the end of slot but within guard */
					in = -in + (AWDL_UNICAST_GUARD_TU*1024.0)/1000.0/1000.0;
                }
			}
        }
    }

    if (OWL_STATE->next_ping_len) {
        // +/- 50 ms
        double noise = (((double) esp_random() * 2 / UINT32_MAX) - 1) * 50 / 1000;
        printf("in noise: %f\n", noise);
        REARM_ONESHOT(ctx, in*1000*1000 + noise); // 50ms early
    } else {
        REARM_ONESHOT(ctx, 100*1000);
    }
}

esp_err_t
owl_init(void)
{
    printf("owl_init start\n");

    log_set_level(LOG_DEBUG);

    printf("initializing led\n");
    led_init();

    printf("initializing netif\n");
    ESP_ERROR_CHECK(esp_netif_init());

    printf("netifs before:\n");
    print_netifs();

    printf("initializing default event loop\n");
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    printf("initializing wifi\n");
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));

    printf("initializing dummy ap\n");
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    wifi_config_t ap_cfg = {
        .ap = {
            .ssid = "esp32-owl-dummy",
            .ssid_len = 0,
            .password = "dummypassword",
            .channel = 6,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .ssid_hidden = 1,
            .max_connection = 4,
            .beacon_interval = 60000,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    OWL_STATE = malloc(sizeof(*OWL_STATE));

    struct ether_addr eaddr = {{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }};

    printf("initializing awdl state\n");

	awdl_init_state(&OWL_STATE->awdl_state, 
        "myhostname", &eaddr, CHAN_OPCLASS_6, clock_time_us());
	OWL_STATE->awdl_state.peer_cb = owl_awdl_neighbor_add;
	OWL_STATE->awdl_state.peer_cb_data = NULL;
	OWL_STATE->awdl_state.peer_remove_cb = owl_awdl_neighbor_remove;
	OWL_STATE->awdl_state.peer_remove_cb_data = NULL;

    printf("initializing ieee80211 state\n");

	ieee80211_init_state(&OWL_STATE->ieee80211_state);

    /*
	OWL_STATE->next = NULL;
	OWL_STATE->tx_queue_multicast = circular_buf_init(16);
	OWL_STATE->dump = dump;
    */

    printf("initialized awdl state\n");

    OWL_STATE->next_ping_buf = malloc(1024);
    OWL_STATE->next_ping_len = 0;

    printf("initializing promiscuous mode\n");
    wifi_promiscuous_filter_t pf = {0};
    pf.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    pf.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&pf));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_rx_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    printf("setting protocol\n");
    ESP_ERROR_CHECK(esp_wifi_set_protocol(WIFI_IF_AP, 
        WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N));

    printf("setting bandwidth\n");
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT40));

    printf("joining channel 6\n");
    ESP_ERROR_CHECK(esp_wifi_set_channel(6, WIFI_SECOND_CHAN_ABOVE));
    OWL_STATE->awdl_state.channel.current = CHAN_OPCLASS_6;

    printf("starting owl timers\n");
    RUN_PERIODIC(send_psf, OWL_STATE->awdl_state.psf_interval * 1024);
    RUN_ONESHOT(send_mif, 1000*1000);
    RUN_ONESHOT(send_ping, 1000*1000);
    // RUN_ONESHOT(send_unicast, 1000*1000);
    xTaskCreate(print_stats_task, "print_stats", 8192, NULL, 2, NULL);

    printf("owl_init done\n");
    return ESP_OK;
}
