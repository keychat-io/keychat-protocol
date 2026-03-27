#!/usr/bin/env node
/**
 * Keychat MCP Server — unified adapter for Claude Code, Codex, and Gemini CLI
 *
 * Architecture:
 *   AI Tool ←stdio MCP→ this server ←HTTP→ keychat agent daemon ←Nostr→ Users
 *
 * The agent daemon handles all encryption (Signal PQXDH + NIP-17 gift-wrap).
 * This server only does MCP ↔ HTTP translation.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as fs from "fs";
import * as path from "path";
import { KeychatClient, type EventHandlers } from "../common/keychat-client.js";

// ─── Configuration ──────────────────────────────────────────

const CHANNELS_DIR =
  process.env.KEYCHAT_CHANNELS_DIR ||
  path.join(
    process.env.HOME || process.env.USERPROFILE || ".",
    ".keychat",
    "mcp"
  );

const CONFIG_FILE = path.join(CHANNELS_DIR, "config.json");
const ACCESS_FILE = path.join(CHANNELS_DIR, "access.json");

interface Config {
  daemonUrl: string;
  apiToken?: string;
}

interface AccessConfig {
  allowFrom: string[];
  autoApproveOwner: boolean;
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

function isAllowed(senderPubkey: string): boolean {
  const access = loadAccess();
  if (access.allowFrom.length === 0 && access.autoApproveOwner) {
    return true;
  }
  return access.allowFrom.includes(senderPubkey);
}

// ─── Client ─────────────────────────────────────────────────

const config = loadConfig();
const client = new KeychatClient({
  daemonUrl: config.daemonUrl,
  apiToken: config.apiToken,
});

// ─── SSE listener ───────────────────────────────────────────

let sseController: AbortController | null = null;

function startSSEListener(server: Server): void {
  if (sseController) sseController.abort();

  const handlers: EventHandlers = {
    onMessage: (data) => {
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
    },

    onFriendRequest: (data) => {
      const content = `Friend request from ${data.sender_name || "unknown"} (${(data.sender_pubkey || "").slice(0, 16)}…). Request ID: ${data.request_id}`;
      server.notification({
        method: "notifications/claude/channel",
        params: {
          content,
          meta: {
            chat_id: "system",
            message_id: data.request_id || "",
            user: data.sender_name || "unknown",
            user_id: data.sender_pubkey || "",
            ts: new Date().toISOString(),
            kind: "friend_request",
          },
        },
      });
    },

    onFriendAccepted: (data) => {
      server.notification({
        method: "notifications/claude/channel",
        params: {
          content: `Friend request accepted by ${data.peer_name || "unknown"}`,
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
    },

    onStatusChange: (data) => {
      console.error(`[keychat] connection_status_changed: ${JSON.stringify(data)}`);
    },

    onEvent: (type, data) => {
      console.error(`[keychat] ${type}: ${JSON.stringify(data)}`);
    },
  };

  sseController = client.subscribe(handlers);
}

// ─── MCP Server ─────────────────────────────────────────────

const mcpServer = new Server(
  { name: "keychat", version: "0.2.0" },
  {
    capabilities: {
      experimental: { "claude/channel": {} },
      tools: {},
    },
  }
);

// ─── Tool definitions ───────────────────────────────────────

mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "reply",
      description: "Send a message to a Keychat room. Pass chat_id from the inbound <channel> message.",
      inputSchema: {
        type: "object" as const,
        properties: {
          chat_id: { type: "string", description: "Room ID to send to" },
          text: { type: "string", description: "Message text to send" },
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
          chat_id: { type: "string", description: "Room ID" },
          limit: { type: "number", description: "Number of messages (default: 20)" },
        },
        required: ["chat_id"],
      },
    },
    {
      name: "list_rooms",
      description: "List all Keychat rooms/conversations.",
      inputSchema: { type: "object" as const, properties: {} },
    },
    {
      name: "list_contacts",
      description: "List all Keychat contacts.",
      inputSchema: { type: "object" as const, properties: {} },
    },
    {
      name: "get_status",
      description: "Get Keychat daemon status (identity, connection, relays).",
      inputSchema: { type: "object" as const, properties: {} },
    },
    {
      name: "get_identity",
      description: "Get agent identity (pubkey, npub, name).",
      inputSchema: { type: "object" as const, properties: {} },
    },
    {
      name: "send_friend_request",
      description: "Send a friend request to a Nostr pubkey.",
      inputSchema: {
        type: "object" as const,
        properties: {
          pubkey: { type: "string", description: "Nostr hex pubkey" },
          name: { type: "string", description: "Display name" },
        },
        required: ["pubkey"],
      },
    },
    {
      name: "pending_friends",
      description: "List pending friend requests waiting for approval.",
      inputSchema: { type: "object" as const, properties: {} },
    },
    {
      name: "approve_friend",
      description: "Approve a pending friend request by request ID.",
      inputSchema: {
        type: "object" as const,
        properties: {
          request_id: { type: "string", description: "Request ID" },
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
          request_id: { type: "string", description: "Request ID" },
        },
        required: ["request_id"],
      },
    },
  ],
}));

// ─── Tool handlers ──────────────────────────────────────────

mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "reply": {
        const chatId = (args as any).chat_id;
        const text = (args as any).text;
        if (!chatId || !text) return errorResult("chat_id and text are required");

        const result = await client.send(chatId, text);
        return result?.ok
          ? textResult(`sent (room: ${chatId.slice(0, 16)}…)`)
          : errorResult(result?.error || "send failed");
      }

      case "fetch_messages": {
        const chatId = (args as any).chat_id;
        const limit = (args as any).limit || 20;
        if (!chatId) return errorResult("chat_id is required");

        const res = await client.messages(chatId, limit);
        if (!res?.ok) return errorResult(res?.error || "fetch failed");

        const formatted = (res.data || [])
          .map((m: any) => {
            const sender = m.is_me_send ? "You" : (m.sender_pubkey || "?").slice(0, 16);
            const status = m.status === "Success" ? "✓" : m.status === "Failed" ? "✗" : "⏳";
            return `[${m.created_at || "?"}] ${sender} ${status}: ${m.content || ""}`;
          })
          .join("\n");
        return textResult(formatted || "(no messages)");
      }

      case "list_rooms": {
        const res = await client.rooms();
        if (!res?.ok) return errorResult(res?.error || "fetch failed");

        const formatted = (res.data || [])
          .map((r: any) => {
            const unread = r.unread_count > 0 ? ` (${r.unread_count})` : "";
            const rname = r.name || r.to_main_pubkey?.slice(0, 16) || "?";
            return `[${r.room_type || "DM"}] ${r.status === "Enabled" ? "●" : "○"} ${rname}${unread} — id:${r.id.slice(0, 16)}…`;
          })
          .join("\n");
        return textResult(formatted || "(no rooms)");
      }

      case "list_contacts": {
        const res = await client.contacts();
        if (!res?.ok) return errorResult(res?.error || "fetch failed");

        const formatted = (res.data || [])
          .map((c: any) => {
            const cname = c.petname || c.name || c.pubkey?.slice(0, 16) || "?";
            return `${cname} — ${c.pubkey?.slice(0, 16)}…`;
          })
          .join("\n");
        return textResult(formatted || "(no contacts)");
      }

      case "get_status": {
        const res = await client.status();
        if (!res?.ok) return errorResult(res?.error || "fetch failed");
        return textResult(JSON.stringify(res.data, null, 2));
      }

      case "get_identity": {
        const res = await client.identity();
        if (!res?.ok) return errorResult(res?.error || "fetch failed");
        return textResult(JSON.stringify(res.data, null, 2));
      }

      case "send_friend_request": {
        const pubkey = (args as any).pubkey;
        if (!pubkey) return errorResult("pubkey is required");
        const res = await client.sendFriendRequest(pubkey, (args as any).name);
        return res?.ok
          ? textResult(`Friend request sent to ${pubkey.slice(0, 16)}…`)
          : errorResult(res?.error || "send failed");
      }

      case "pending_friends": {
        const res = await client.pendingFriends();
        if (!res?.ok) return errorResult(res?.error || "fetch failed");
        const pending = res.data || [];
        if (pending.length === 0) return textResult("(no pending friend requests)");
        const formatted = pending
          .map((p: any) => `${p.sender_name || "unknown"} (${(p.sender_pubkey || "").slice(0, 16)}…) — id:${p.request_id}`)
          .join("\n");
        return textResult(formatted);
      }

      case "approve_friend": {
        const requestId = (args as any).request_id;
        if (!requestId) return errorResult("request_id is required");
        const res = await client.approveFriend(requestId);
        return res?.ok
          ? textResult(`Approved. Sender: ${res.data?.sender_pubkey?.slice(0, 16) || "?"}…`)
          : errorResult(res?.error || "approve failed");
      }

      case "reject_friend": {
        const requestId = (args as any).request_id;
        if (!requestId) return errorResult("request_id is required");
        const res = await client.rejectFriend(requestId);
        return res?.ok ? textResult("Rejected.") : errorResult(res?.error || "reject failed");
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
  fs.mkdirSync(CHANNELS_DIR, { recursive: true });

  try {
    const res = await client.status();
    if (res?.ok) {
      console.error(`[keychat] Connected to daemon at ${config.daemonUrl}`);
      if (res.data?.identity) {
        console.error(`[keychat] Identity: ${res.data.identity.slice(0, 16)}…`);
      }
    } else {
      console.error(`[keychat] Warning: daemon at ${config.daemonUrl} returned error. Start it with: keychat agent`);
    }
  } catch {
    console.error(`[keychat] Warning: cannot reach daemon at ${config.daemonUrl}. Start it with: keychat agent`);
  }

  startSSEListener(mcpServer);

  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
  console.error("[keychat] MCP server started");

  process.on("SIGINT", () => { sseController?.abort(); process.exit(0); });
  process.on("SIGTERM", () => { sseController?.abort(); process.exit(0); });
}

main().catch((err) => {
  console.error(`[keychat] Fatal: ${err.message}`);
  process.exit(1);
});
