/**
 * keychat-client.ts — Shared TypeScript client for Keychat agent daemon
 *
 * Used by the MCP server and any TypeScript-based adapter.
 */

import { createParser, type EventSourceMessage } from "eventsource-parser";

// ─── Types ──────────────────────────────────────────────────

export interface KeychatConfig {
  daemonUrl: string;
  apiToken?: string;
}

export interface EventHandlers {
  onMessage?: (data: any) => void;
  onFriendRequest?: (data: any) => void;
  onFriendAccepted?: (data: any) => void;
  onPendingFriend?: (data: any) => void;
  onStatusChange?: (data: any) => void;
  onEvent?: (type: string, data: any) => void;
}

// ─── Client ─────────────────────────────────────────────────

export class KeychatClient {
  private daemonUrl: string;
  private apiToken?: string;

  constructor(config: KeychatConfig) {
    this.daemonUrl = config.daemonUrl;
    this.apiToken = config.apiToken;
  }

  // ── HTTP helpers ──────────────────────────────────────────

  private authHeaders(extra?: Record<string, string>): Record<string, string> {
    const headers: Record<string, string> = { ...extra };
    if (this.apiToken) {
      headers["Authorization"] = `Bearer ${this.apiToken}`;
    }
    return headers;
  }

  async get(path: string): Promise<any> {
    const res = await fetch(`${this.daemonUrl}${path}`, {
      headers: this.authHeaders(),
    });
    return res.json();
  }

  async post(path: string, body?: any): Promise<any> {
    const res = await fetch(`${this.daemonUrl}${path}`, {
      method: "POST",
      headers: this.authHeaders({ "Content-Type": "application/json" }),
      body: body ? JSON.stringify(body) : undefined,
    });
    return res.json();
  }

  // ── Convenience methods ───────────────────────────────────

  identity() {
    return this.get("/identity");
  }

  status() {
    return this.get("/status");
  }

  rooms() {
    return this.get("/rooms");
  }

  messages(roomId: string, limit = 50) {
    return this.get(`/rooms/${roomId}/messages?limit=${limit}`);
  }

  contacts() {
    return this.get("/contacts");
  }

  relays() {
    return this.get("/relays");
  }

  send(roomId: string, text: string) {
    return this.post("/send", { room_id: roomId, text });
  }

  sendFriendRequest(pubkey: string, name?: string) {
    return this.post("/friend-request", { pubkey, name: name || "" });
  }

  // ── Agent-specific ────────────────────────────────────────

  pendingFriends() {
    return this.get("/pending-friends");
  }

  approveFriend(requestId: string) {
    return this.post("/approve-friend", { request_id: requestId });
  }

  rejectFriend(requestId: string) {
    return this.post("/reject-friend", { request_id: requestId });
  }

  owner() {
    return this.get("/owner");
  }

  // ── SSE subscription ─────────────────────────────────────

  subscribe(handlers: EventHandlers): AbortController {
    const controller = new AbortController();
    const tokenParam = this.apiToken ? `?token=${this.apiToken}` : "";
    const url = `${this.daemonUrl}/events${tokenParam}`;

    const connect = () => {
      if (controller.signal.aborted) return;

      fetch(url, {
        signal: controller.signal,
        headers: this.authHeaders({ Accept: "text/event-stream" }),
      })
        .then(async (res) => {
          if (!res.ok || !res.body) {
            console.error(`[keychat] SSE failed: ${res.status}. Retrying...`);
            setTimeout(connect, 5000);
            return;
          }

          const parser = createParser({
            onEvent: (event: EventSourceMessage) => {
              if (!event.data) return;
              let data: any;
              try {
                data = JSON.parse(event.data);
              } catch {
                return;
              }

              switch (event.event) {
                case "message_received":
                  handlers.onMessage?.(data);
                  break;
                case "friend_request_received":
                  handlers.onFriendRequest?.(data);
                  break;
                case "friend_request_accepted":
                  handlers.onFriendAccepted?.(data);
                  break;
                case "pending_friend_request":
                  handlers.onPendingFriend?.(data);
                  break;
                case "connection_status_changed":
                  handlers.onStatusChange?.(data);
                  break;
                default:
                  handlers.onEvent?.(event.event || "unknown", data);
                  break;
              }
            },
          });

          const reader = res.body.getReader();
          const decoder = new TextDecoder();

          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              parser.feed(decoder.decode(value, { stream: true }));
            }
          } catch (err: any) {
            if (err.name !== "AbortError") {
              console.error(`[keychat] SSE read error: ${err.message}`);
            }
          }

          if (!controller.signal.aborted) {
            console.error("[keychat] SSE disconnected. Reconnecting in 3s...");
            setTimeout(connect, 3000);
          }
        })
        .catch((err: any) => {
          if (err.name !== "AbortError") {
            console.error(`[keychat] SSE error: ${err.message}. Retrying...`);
            setTimeout(connect, 5000);
          }
        });
    };

    connect();
    return controller;
  }

  // ── Session routing ───────────────────────────────────────

  static sessionId(senderPubkey: string, groupId?: string): string {
    if (groupId && groupId !== "null") {
      return `kcv2_sg_${groupId}`;
    }
    return `kcv2_dm_${senderPubkey}`;
  }
}
