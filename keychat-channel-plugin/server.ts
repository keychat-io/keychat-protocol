#!/usr/bin/env node
/**
 * Keychat Channel Plugin for Claude Code
 *
 * Bridges Claude Code ↔ keychat-cli daemon via HTTP API + SSE.
 *
 * Architecture:
 *   Claude Code ←stdio MCP→ this plugin ←HTTP→ keychat-cli daemon ←Nostr→ Relay
 *
 * The daemon handles all encryption (Signal PQXDH + NIP-17 gift-wrap).
 * This plugin only does MCP ↔ HTTP translation.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createParser, type EventSourceMessage } from "eventsource-parser";
import * as fs from "fs";
import * as path from "path";

// ─── Configuration ──────────────────────────────────────────

const CHANNELS_DIR =
  process.env.KEYCHAT_CHANNELS_DIR ||
  path.join(
    process.env.HOME || process.env.USERPROFILE || ".",
    ".claude",
    "channels",
    "keychat"
  );

const CONFIG_FILE = path.join(CHANNELS_DIR, "config.json");
const ACCESS_FILE = path.join(CHANNELS_DIR, "access.json");

interface Config {
  daemonUrl: string; // e.g. "http://127.0.0.1:10443"
  apiToken?: string; // Bearer token for agent daemon auth
}

interface AccessConfig {
  allowFrom: string[]; // allowed sender pubkeys (hex)
  autoApproveOwner: boolean; // auto-approve if sender is daemon owner
}

function loadConfig(): Config {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return { daemonUrl: "http://127.0.0.1:10443" };
  }
}

function saveConfig(config: Config): void {
  fs.mkdirSync(CHANNELS_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

function loadAccess(): AccessConfig {
  try {
    const raw = fs.readFileSync(ACCESS_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return { allowFrom: [], autoApproveOwner: true };
  }
}

function saveAccess(access: AccessConfig): void {
  fs.mkdirSync(CHANNELS_DIR, { recursive: true });
  fs.writeFileSync(ACCESS_FILE, JSON.stringify(access, null, 2));
}

function isAllowed(senderPubkey: string): boolean {
  const access = loadAccess();
  if (access.allowFrom.length === 0 && access.autoApproveOwner) {
    // If no allowlist, allow all (daemon already handles owner logic)
    return true;
  }
  return access.allowFrom.includes(senderPubkey);
}

// ─── HTTP helpers ───────────────────────────────────────────

const config = loadConfig();

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...extra };
  if (config.apiToken) {
    headers["Authorization"] = `Bearer ${config.apiToken}`;
  }
  return headers;
}

async function daemonGet(path: string): Promise<any> {
  const url = `${config.daemonUrl}${path}`;
  const res = await fetch(url, { headers: authHeaders() });
  return res.json();
}

async function daemonPost(path: string, body?: any): Promise<any> {
  const url = `${config.daemonUrl}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

// ─── SSE listener ───────────────────────────────────────────

let sseAbortController: AbortController | null = null;

function startSSEListener(server: Server): void {
  if (sseAbortController) {
    sseAbortController.abort();
  }
  sseAbortController = new AbortController();
  const signal = sseAbortController.signal;

  // SSE: use ?token= query param (some fetch implementations drop headers on streaming)
  const tokenParam = config.apiToken ? `?token=${config.apiToken}` : "";
  const url = `${config.daemonUrl}/events${tokenParam}`;

  const connectSSE = () => {
    if (signal.aborted) return;

    fetch(url, { signal, headers: authHeaders({ Accept: "text/event-stream" }) })
      .then(async (res) => {
        if (!res.ok || !res.body) {
          console.error(
            `[keychat] SSE connection failed: ${res.status}. Retrying in 5s...`
          );
          setTimeout(connectSSE, 5000);
          return;
        }

        const parser = createParser({
          onEvent: (event: EventSourceMessage) => {
            handleSSEEvent(server, event);
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

        // Reconnect after disconnect
        if (!signal.aborted) {
          console.error("[keychat] SSE disconnected. Reconnecting in 3s...");
          setTimeout(connectSSE, 3000);
        }
      })
      .catch((err: any) => {
        if (err.name !== "AbortError") {
          console.error(
            `[keychat] SSE connect error: ${err.message}. Retrying in 5s...`
          );
          setTimeout(connectSSE, 5000);
        }
      });
  };

  connectSSE();
}

function handleSSEEvent(server: Server, event: EventSourceMessage): void {
  if (!event.data) return;

  let data: any;
  try {
    data = JSON.parse(event.data);
  } catch {
    return;
  }

  switch (event.event) {
    case "message_received": {
      const senderPubkey = data.sender_pubkey || "";
      if (!isAllowed(senderPubkey)) {
        console.error(
          `[keychat] Blocked message from non-allowed sender: ${senderPubkey.slice(0, 16)}...`
        );
        return;
      }

      const content = data.content || data.fallback || "";
      const meta: Record<string, string> = {
        chat_id: data.room_id || "",
        message_id: data.event_id || "",
        user: senderPubkey.slice(0, 16),
        user_id: senderPubkey,
        ts: new Date().toISOString(),
      };
      if (data.group_id) meta.group_id = data.group_id;
      if (data.kind) meta.kind = data.kind;
      if (data.room_id) meta.room_id = data.room_id;

      server.notification({
        method: "notifications/claude/channel",
        params: { content, meta },
      });
      break;
    }

    case "friend_request_received": {
      const content = `Friend request from ${data.sender_name || "unknown"} (${(data.sender_pubkey || "").slice(0, 16)}…). Message: ${data.message || "(none)"}. Request ID: ${data.request_id}`;
      const meta: Record<string, string> = {
        chat_id: "system",
        message_id: data.request_id || "",
        user: data.sender_name || "unknown",
        user_id: data.sender_pubkey || "",
        ts: new Date().toISOString(),
        kind: "friend_request",
      };

      server.notification({
        method: "notifications/claude/channel",
        params: { content, meta },
      });
      break;
    }

    case "friend_request_accepted": {
      const content = `Friend request accepted by ${data.peer_name || "unknown"}`;
      server.notification({
        method: "notifications/claude/channel",
        params: {
          content,
          meta: {
            chat_id: "system",
            message_id: "",
            user: "system",
            user_id: "",
            ts: new Date().toISOString(),
            kind: "friend_accepted",
          },
        },
      });
      break;
    }

    // Other events logged but not forwarded as channel messages
    case "connection_status_changed":
    case "relay_ok":
    case "event_loop_error":
      console.error(`[keychat] ${event.event}: ${event.data}`);
      break;
  }
}

// ─── MCP Server ─────────────────────────────────────────────

const server = new Server(
  {
    name: "keychat",
    version: "0.1.0",
  },
  {
    capabilities: {
      experimental: {
        "claude/channel": {},
      },
      tools: {},
    },
  }
);

// ─── Tool definitions ───────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "reply",
      description:
        "Send a message to a Keychat room. Pass chat_id from the inbound <channel> message.",
      inputSchema: {
        type: "object" as const,
        properties: {
          chat_id: {
            type: "string",
            description: "Room ID to send to (from inbound message chat_id)",
          },
          text: {
            type: "string",
            description: "Message text to send",
          },
          reply_to: {
            type: "string",
            description: "Optional event_id to reply to",
          },
        },
        required: ["chat_id", "text"],
      },
    },
    {
      name: "fetch_messages",
      description: "Fetch recent messages from a Keychat room.",
      inputSchema: {
        type: "object" as const,
        properties: {
          chat_id: {
            type: "string",
            description: "Room ID",
          },
          limit: {
            type: "number",
            description: "Number of messages to fetch (default: 20)",
          },
        },
        required: ["chat_id"],
      },
    },
    {
      name: "list_rooms",
      description: "List all Keychat rooms/conversations.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "list_contacts",
      description: "List all Keychat contacts.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "get_status",
      description:
        "Get Keychat daemon status (identity, connection, relays).",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "get_identity",
      description: "Get agent identity (pubkey, npub, name).",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "send_friend_request",
      description: "Send a friend request to a Nostr pubkey.",
      inputSchema: {
        type: "object" as const,
        properties: {
          pubkey: {
            type: "string",
            description: "Nostr hex pubkey of the user to add",
          },
          name: {
            type: "string",
            description: "Display name to show in the request",
          },
        },
        required: ["pubkey"],
      },
    },
    {
      name: "pending_friends",
      description: "List pending friend requests waiting for approval.",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
    {
      name: "approve_friend",
      description: "Approve a pending friend request by request ID.",
      inputSchema: {
        type: "object" as const,
        properties: {
          request_id: {
            type: "string",
            description: "Request ID from pending_friends list",
          },
        },
        required: ["request_id"],
      },
    },
    {
      name: "reject_friend",
      description: "Reject a pending friend request by request ID.",
      inputSchema: {
        type: "object" as const,
        properties: {
          request_id: {
            type: "string",
            description: "Request ID from pending_friends list",
          },
        },
        required: ["request_id"],
      },
    },
  ],
}));

// ─── Tool handlers ──────────────────────────────────────────

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "reply": {
        const chatId = (args as any).chat_id;
        const text = (args as any).text;
        if (!chatId || !text) {
          return errorResult("chat_id and text are required");
        }

        const result = await daemonPost("/send", {
          room_id: chatId,
          text,
        });

        if (result?.ok) {
          return textResult(`sent (room: ${chatId.slice(0, 16)}…)`);
        } else {
          return errorResult(result?.error || "send failed");
        }
      }

      case "fetch_messages": {
        const chatId = (args as any).chat_id;
        const limit = (args as any).limit || 20;
        if (!chatId) {
          return errorResult("chat_id is required");
        }

        const res = await daemonGet(
          `/rooms/${chatId}/messages?limit=${limit}`
        );
        if (!res?.ok) {
          return errorResult(res?.error || "fetch failed");
        }

        const messages = res.data || [];
        const formatted = messages
          .map((m: any) => {
            const sender = m.is_me_send
              ? "You"
              : (m.sender_pubkey || "?").slice(0, 16);
            const status =
              m.status === "Success"
                ? "✓"
                : m.status === "Failed"
                  ? "✗"
                  : "⏳";
            return `[${m.created_at || "?"}] ${sender} ${status}: ${m.content || ""}`;
          })
          .join("\n");

        return textResult(formatted || "(no messages)");
      }

      case "list_rooms": {
        const res = await daemonGet("/rooms");
        if (!res?.ok) {
          return errorResult(res?.error || "fetch failed");
        }

        const rooms = res.data || [];
        const formatted = rooms
          .map((r: any) => {
            const type = r.room_type || "DM";
            const unread = r.unread_count > 0 ? ` (${r.unread_count})` : "";
            const name = r.name || r.to_main_pubkey?.slice(0, 16) || "?";
            return `[${type}] ${r.status === "Enabled" ? "●" : "○"} ${name}${unread} — id:${r.id.slice(0, 16)}…`;
          })
          .join("\n");

        return textResult(formatted || "(no rooms)");
      }

      case "list_contacts": {
        const res = await daemonGet("/contacts");
        if (!res?.ok) {
          return errorResult(res?.error || "fetch failed");
        }

        const contacts = res.data || [];
        const formatted = contacts
          .map((c: any) => {
            const name =
              c.petname || c.name || c.pubkey?.slice(0, 16) || "?";
            return `${name} — ${c.pubkey?.slice(0, 16)}…`;
          })
          .join("\n");

        return textResult(formatted || "(no contacts)");
      }

      case "get_status": {
        const res = await daemonGet("/status");
        if (!res?.ok) {
          return errorResult(res?.error || "fetch failed");
        }
        return textResult(JSON.stringify(res.data, null, 2));
      }

      case "get_identity": {
        const res = await daemonGet("/identity");
        if (!res?.ok) {
          return errorResult(res?.error || "fetch failed");
        }
        return textResult(JSON.stringify(res.data, null, 2));
      }

      case "send_friend_request": {
        const pubkey = (args as any).pubkey;
        const name = (args as any).name || "";
        if (!pubkey) {
          return errorResult("pubkey is required");
        }
        const res = await daemonPost("/friend-request", { pubkey, name });
        if (res?.ok) {
          return textResult(`Friend request sent to ${pubkey.slice(0, 16)}…`);
        } else {
          return errorResult(res?.error || "send failed");
        }
      }

      case "pending_friends": {
        const res = await daemonGet("/pending-friends");
        if (!res?.ok) {
          return errorResult(res?.error || "fetch failed");
        }
        const pending = res.data || [];
        if (pending.length === 0) {
          return textResult("(no pending friend requests)");
        }
        const formatted = pending
          .map((p: any) => {
            const name = p.sender_name || "unknown";
            const pk = (p.sender_pubkey || "").slice(0, 16);
            return `${name} (${pk}…) — id:${p.request_id}`;
          })
          .join("\n");
        return textResult(formatted);
      }

      case "approve_friend": {
        const requestId = (args as any).request_id;
        if (!requestId) {
          return errorResult("request_id is required");
        }
        const res = await daemonPost("/approve-friend", {
          request_id: requestId,
        });
        if (res?.ok) {
          return textResult(
            `Approved. Sender: ${res.data?.sender_pubkey?.slice(0, 16) || "?"}…`
          );
        } else {
          return errorResult(res?.error || "approve failed");
        }
      }

      case "reject_friend": {
        const requestId = (args as any).request_id;
        if (!requestId) {
          return errorResult("request_id is required");
        }
        const res = await daemonPost("/reject-friend", {
          request_id: requestId,
        });
        if (res?.ok) {
          return textResult("Rejected.");
        } else {
          return errorResult(res?.error || "reject failed");
        }
      }

      default:
        return errorResult(`Unknown tool: ${name}`);
    }
  } catch (err: any) {
    return errorResult(`Daemon error: ${err.message}`);
  }
});

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function errorResult(msg: string) {
  return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
}

// ─── Startup ────────────────────────────────────────────────

async function main() {
  // Ensure channels dir exists
  fs.mkdirSync(CHANNELS_DIR, { recursive: true });

  // Check if daemon is reachable
  try {
    const res = await daemonGet("/status");
    if (res?.ok) {
      console.error(
        `[keychat] Connected to daemon at ${config.daemonUrl}`
      );
      if (res.data?.identity) {
        console.error(
          `[keychat] Identity: ${res.data.identity.slice(0, 16)}…`
        );
      }
    } else {
      console.error(
        `[keychat] Warning: daemon at ${config.daemonUrl} returned error. Start it with: keychat agent`
      );
    }
  } catch {
    console.error(
      `[keychat] Warning: cannot reach daemon at ${config.daemonUrl}. Start it with: keychat agent`
    );
  }

  // Start SSE listener for incoming messages
  startSSEListener(server);

  // Connect MCP transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("[keychat] Channel plugin started");

  // Cleanup on exit
  process.on("SIGINT", () => {
    sseAbortController?.abort();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    sseAbortController?.abort();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error(`[keychat] Fatal: ${err.message}`);
  process.exit(1);
});
