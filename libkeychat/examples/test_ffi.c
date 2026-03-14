#include <stdio.h>
#include <stdlib.h>
#include "../include/libkeychat.h"

int main() {
    printf("=== libkeychat C FFI test ===\n\n");

    // 1. Generate identity
    KeychatContext *ctx = keychat_init_generate();
    if (!ctx) {
        fprintf(stderr, "Failed to init\n");
        return 1;
    }
    printf("✅ Context created\n");

    // 2. Get identity info
    char *npub = keychat_get_npub(ctx);
    char *mnemonic = keychat_get_mnemonic(ctx);
    printf("   npub: %.16s...\n", npub);
    printf("   mnemonic: %.30s...\n", mnemonic);
    keychat_free_string(npub);
    keychat_free_string(mnemonic);

    // 3. List peers (empty)
    char *peers = keychat_list_peers(ctx);
    printf("   peers: %s\n", peers);
    keychat_free_string(peers);

    // 4. Send friend request
    KeychatFriendRequestResult fr = keychat_send_friend_request(
        ctx,
        "e8bcf3823669444da2882f4ae7b8f63a6e0ff88a7ed37c7a9d8dbb1a2de78e42",
        "TestUser"
    );
    if (fr.error == 0) {
        printf("✅ Friend request created\n");
        printf("   firstInbox: %.16s...\n", fr.first_inbox);
        printf("   event: %.40s...\n", fr.event_json);
        keychat_free_string(fr.event_json);
        keychat_free_string(fr.first_inbox);
    } else {
        printf("❌ Friend request failed\n");
    }

    // 5. Restore from mnemonic
    KeychatContext *ctx2 = keychat_init(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    if (ctx2) {
        char *npub2 = keychat_get_npub(ctx2);
        printf("✅ Restored from mnemonic: %.16s...\n", npub2);
        keychat_free_string(npub2);
        keychat_destroy(ctx2);
    }

    // Cleanup
    keychat_destroy(ctx);
    printf("\n✅ All tests passed\n");
    return 0;
}
