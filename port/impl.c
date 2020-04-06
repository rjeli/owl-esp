#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "driver/gpio.h"

#include "../src/state.h"
#include "../src/rx.h"
#include "../src/log.h"

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
};
struct owl_state *OWL_STATE = NULL;

// fns

int
owl_addone(int x)
{
    return x + 1;
}

static void
wifi_rx_cb(void *_pkt, wifi_promiscuous_pkt_type_t type)
{
	uint64_t tsft = clock_time_us();

    wifi_promiscuous_pkt_t *pkt = _pkt;
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

	int ret = awdl_rx_action(frame, pkt->rx_ctrl.rssi, tsft, from, to, &OWL_STATE->awdl_state);
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
	        stats->tx_action, stats->tx_data, stats->tx_data_unicast, stats->tx_data_multicast);
	    printf(" RX action %llu, data %llu, unknown %llu\n",
	        stats->rx_action, stats->rx_data, stats->rx_unknown);
        printf("=== PEERS ===\n");
        int len = awdl_peers_print(peers, peer_print_buf, 4096);
        peer_print_buf[len] = '\0';
        printf("%s\n", peer_print_buf);
        vTaskDelay(5000/portTICK_RATE_MS);
    }
}

esp_err_t
owl_init(void)
{
    printf("owl_init start\n");

    log_set_level(LOG_TRACE);

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

    printf("initializing promiscuous mode\n");
    wifi_promiscuous_filter_t pf = {0};
    pf.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    pf.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&pf));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_rx_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    printf("joining channel 6\n");
    ESP_ERROR_CHECK(esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE));

    xTaskCreate(print_stats_task, "print_stats", 8192, NULL, 2, NULL);

    printf("owl_init done\n");
    return ESP_OK;
}
