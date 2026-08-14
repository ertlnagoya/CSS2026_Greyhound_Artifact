#ifndef __EAPModule
#define __EAPModule

#include <stddef.h>
#include "common.h"
#include "wpabuf.h"

struct peer_response
{
    struct wpabuf *response;
    const u8 *key;
    size_t key_len;
    u8 key_available;
};

int eap_peer_init(const u8 *username, const u8 *password, const u8 *certificate_file);
void eap_peer_rx(const u8 *data, size_t data_len);
struct peer_response eap_peer_step(void);
void eap_peer_reset();
void eap_peer_deinit(void);

#endif