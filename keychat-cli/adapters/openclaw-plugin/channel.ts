/**
 * Keychat CLI channel plugin — core implementation.
 *
 * Connects to keychat-cli agent daemon via HTTP API:
 *   GET  /events   — SSE stream for inbound messages
 *   POST /send     — send message to a room
 *   GET  /identity — agent npub/pubkey
 *   GET  /owner    — owner pubkey
 *   GET  /rooms    — room list
 */

import {
  emptyPluginConfigSchema,
  type ChannelPlugin,
  type ChannelGatewayContext,
  type ChannelAccountSnapshot,
} from "openclaw/plugin-sdk";

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

const CHANNEL_ID = "keychat-cli";
const DEFAULT_URL = "http://127.0.0.1:7800";
const DEFAULT_ACCOUNT_ID = "default";

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface ChannelConfig {
  enabled?: boolean;
  url?: string;
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: Array<string | number>;
}

interface ResolvedAccount {
  accountId: string;
  enabled: boolean;
  configured: boolean;
  url: string;
  dmPolicy: string;
  allowFrom: Array<string | number>;
}

interface DaemonIdentity {
  npub: string;
  pubkey_hex: string;
  name?: string;
}

interface SseEvent {
  type?: string;
  room_id?: string;
  sender_pubkey?: string;
  sender_name?: string;
  content?: string;
  kind?: string;
  group_id?: string;
  event_id?: string;
  request_id?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════════════════════

function getChannelConfig(cfg: any): ChannelConfig | undefined {
  return (cfg.channels as Record<string, unknown> | undefined)?.[CHANNEL_ID] as ChannelConfig | undefined;
}

function resolveAccount(cfg: any, accountId?: string | null): ResolvedAccount {
  const cc = getChannelConfig(cfg) ?? {};
  return {
    accountId: accountId ?? DEFAULT_ACCOUNT_ID,
    enabled: cc.enabled !== false,
    configured: true,
    url: cc.url ?? DEFAULT_URL,
    dmPolicy: cc.dmPolicy ?? "pairing",
    allowFrom: cc.allowFrom ?? [],
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP client
// ═══════════════════════════════════════════════════════════════════════════

function daemonFetch(url: string, path: string, init?: RequestInit): Promise<Response> {
  const base = url.replace(/\/+$/, "");
  return fetch(`${base}${path}`, init);
}

async function daemonJson<T>(url: string, path: string): Promise<T> {
  const res = await daemonFetch(url, path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  const body = await res.json() as { ok: boolean; data?: T; error?: string };
  if (!body.ok) throw new Error(`${path}: ${body.error ?? "unknown"}`);
  return body.data as T;
}

async function daemonSend(url: string, roomId: string, text: string): Promise<void> {
  const res = await daemonFetch(url, "/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ room_id: roomId, text }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`/send ${res.status}: ${body}`);
  }
}

async function fetchIdentity(url: string): Promise<DaemonIdentity> {
  const data = await daemonJson<{ pubkey_hex: string; npub: string; name?: string }>(url, "/identity");
  return { pubkey_hex: data.pubkey_hex, npub: data.npub, name: data.name };
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE
// ═══════════════════════════════════════════════════════════════════════════

interface SseConnection { stop: () => void; }

function connectSse(
  url: string,
  onEvent: (event: string, data: SseEvent) => void,
  log?: { info: (m: string) => void; warn: (m: string) => void; error: (m: string) => void },
  abortSignal?: AbortSignal,
): SseConnection {
  let stopped = false;
  let controller = new AbortController();
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let reconnectMs = 1000;

  async function connect() {
    if (stopped) return;
    try {
      const sseUrl = `${url.replace(/\/+$/, "")}/events`;
      log?.info(`SSE connecting to ${sseUrl}`);
      const res = await fetch(sseUrl, { headers: { Accept: "text/event-stream" }, signal: controller.signal });
      if (!res.ok) throw new Error(`SSE ${res.status}`);
      if (!res.body) throw new Error("SSE no body");
      reconnectMs = 1000;
      log?.info("SSE connected");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let currentEvent = "";

      while (!stopped) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.startsWith("event:")) {
            currentEvent = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            const raw = line.slice(5).trim();
            if (!raw) continue;
            try {
              const data = JSON.parse(raw) as SseEvent;
              onEvent(currentEvent || data.type || "message", data);
            } catch { log?.warn(`SSE parse error: ${raw.slice(0, 100)}`); }
            currentEvent = "";
          } else if (line === "") { currentEvent = ""; }
        }
      }
    } catch (err: unknown) {
      if (stopped) return;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("abort")) return;
      log?.warn(`SSE disconnected: ${msg}, retry in ${reconnectMs}ms`);
    }
    if (!stopped) {
      reconnectTimer = setTimeout(() => { reconnectMs = Math.min(reconnectMs * 2, 30000); connect(); }, reconnectMs);
    }
  }

  abortSignal?.addEventListener("abort", () => { stopped = true; controller.abort(); if (reconnectTimer) clearTimeout(reconnectTimer); });
  connect();
  return { stop() { stopped = true; controller.abort(); if (reconnectTimer) clearTimeout(reconnectTimer); } };
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime state
// ═══════════════════════════════════════════════════════════════════════════

let pluginRuntime: any = null;
const activeConnections = new Map<string, SseConnection>();
const identityCache = new Map<string, DaemonIdentity>();

export function setRuntime(rt: any) { pluginRuntime = rt; }
function getRuntime() { if (!pluginRuntime) throw new Error("runtime not set"); return pluginRuntime; }

// ═══════════════════════════════════════════════════════════════════════════
// DM policy
// ═══════════════════════════════════════════════════════════════════════════

function normalizePubkey(input: string): string {
  return input.replace(/^nostr:/i, "").replace(/^keychat-cli:/i, "").trim().toLowerCase();
}

function checkAccess(account: ResolvedAccount, sender: string): "allow" | "block" | "pairing" {
  if (account.dmPolicy === "open") return "allow";
  if (account.dmPolicy === "disabled") return "block";
  const norm = normalizePubkey(sender);
  const list = account.allowFrom.map((e) => normalizePubkey(String(e)));
  if (list.includes("*") || list.includes(norm)) return "allow";
  if (account.dmPolicy === "allowlist") return "block";
  return "pairing";
}

// ═══════════════════════════════════════════════════════════════════════════
// Channel plugin
// ═══════════════════════════════════════════════════════════════════════════

export const keychatCliPlugin: ChannelPlugin<ResolvedAccount> = {
  id: CHANNEL_ID,
  meta: {
    id: CHANNEL_ID, label: "Keychat CLI", selectionLabel: "Keychat CLI",
    docsPath: "/channels/keychat-cli", docsLabel: "keychat-cli",
    blurb: "E2E encrypted messaging via keychat-cli daemon.", order: 57,
  },
  capabilities: { chatTypes: ["direct", "group"] },
  reload: { configPrefixes: [`channels.${CHANNEL_ID}`] },
  configSchema: emptyPluginConfigSchema(),

  config: {
    listAccountIds: (cfg) => { const cc = getChannelConfig(cfg); return cc && cc.enabled !== false ? [DEFAULT_ACCOUNT_ID] : []; },
    resolveAccount: (cfg, accountId) => resolveAccount(cfg, accountId),
    defaultAccountId: () => DEFAULT_ACCOUNT_ID,
    isConfigured: (account) => account.configured,
    isEnabled: (account) => account.enabled,
    describeAccount: (account) => ({ accountId: account.accountId, enabled: account.enabled, configured: account.configured, dmPolicy: account.dmPolicy }),
    resolveAllowFrom: ({ cfg, accountId }) => resolveAccount(cfg, accountId).allowFrom.map(String),
    formatAllowFrom: ({ allowFrom }) => allowFrom.map((e) => normalizePubkey(String(e))).filter(Boolean),
  },

  pairing: { idLabel: "keychatPubkey", normalizeAllowEntry: normalizePubkey },

  security: {
    resolveDmPolicy: ({ account }) => ({
      policy: account.dmPolicy, allowFrom: account.allowFrom ?? [],
      policyPath: `channels.${CHANNEL_ID}.dmPolicy`, allowFromPath: `channels.${CHANNEL_ID}.allowFrom`,
      approveHint: `/approve ${CHANNEL_ID} <pubkey>`, normalizeEntry: normalizePubkey,
    }),
  },

  messaging: {
    normalizeTarget: normalizePubkey,
    targetResolver: {
      looksLikeId: (input) => { const t = input.trim(); return t.startsWith("npub1") || /^[0-9a-fA-F]{64}$/.test(t); },
      hint: "<npub or hex pubkey>",
    },
  },

  outbound: {
    deliveryMode: "direct",
    textChunkLimit: 4000,
    sendText: async ({ to, text, accountId }) => {
      const cfg = getRuntime().config.loadConfig();
      const account = resolveAccount(cfg, accountId);
      await daemonSend(account.url, normalizePubkey(to), text ?? "");
      return { channel: CHANNEL_ID as any, to: normalizePubkey(to), messageId: `kc-${Date.now()}` };
    },
  },

  status: {
    buildAccountSnapshot: async ({ account }) => {
      const snapshot: ChannelAccountSnapshot = { accountId: account.accountId, enabled: account.enabled, configured: account.configured, dmPolicy: account.dmPolicy };
      const cached = identityCache.get(account.accountId);
      if (cached) snapshot.publicKey = cached.pubkey_hex;
      return snapshot;
    },
  },

  gateway: {
    startAccount: async (ctx: ChannelGatewayContext<ResolvedAccount>) => {
      const { account } = ctx;
      ctx.log?.info(`Starting keychat-cli (${account.url})`);
      activeConnections.get(account.accountId)?.stop();

      try {
        const id = await fetchIdentity(account.url);
        identityCache.set(account.accountId, id);
        ctx.log?.info(`Identity: ${id.npub}`);
        ctx.setStatus({ accountId: account.accountId, publicKey: id.pubkey_hex, running: true, connected: true, lastStartAt: Date.now() });
      } catch (err) {
        ctx.log?.error(`Identity fetch failed: ${err}`);
        ctx.setStatus({ accountId: account.accountId, running: true, connected: false, lastError: String(err) });
      }

      const core = ctx.channelRuntime;
      if (!core) { ctx.log?.error("channelRuntime unavailable"); return; }

      const connection = connectSse(account.url, async (eventType, data) => {
        // ─── Friend request handling ───────────────────────
        if (eventType === "friend_request_received" || eventType === "pending_friend_request") {
          const senderPk = data.sender_pubkey ?? "";
          const senderNm = data.sender_name ?? senderPk.slice(0, 16);
          const reqId = data.request_id ?? "";
          ctx.log?.info(`Friend request from ${senderNm} (${senderPk.slice(0, 16)})`);

          try {
            const ownerData = await daemonJson<{ owner?: string | null }>(account.url, "/owner");
            // Owner's own request → auto-add to allowFrom
            if (ownerData.owner && normalizePubkey(ownerData.owner) === normalizePubkey(senderPk)) {
              ctx.log?.info(`Owner ${senderNm} auto-added to allowFrom`);
              const cfg = getRuntime().config.loadConfig();
              const currentAllowFrom: string[] = (cfg.channels?.[CHANNEL_ID]?.allowFrom ?? []).map(String);
              if (!currentAllowFrom.includes(normalizePubkey(senderPk)) && !currentAllowFrom.includes("*")) {
                currentAllowFrom.push(normalizePubkey(senderPk));
                getRuntime().config.patchConfig({ channels: { [CHANNEL_ID]: { allowFrom: currentAllowFrom } } });
              }
              return;
            }

            // Non-owner → notify owner
            if (ownerData.owner) {
              const rooms = await daemonJson<Array<{ id: string; to_main_pubkey: string; status: string }>>(account.url, "/rooms");
              const ownerRoom = (rooms ?? []).find((r) => r.to_main_pubkey === ownerData.owner && r.status === "enabled");
              const notifyText = `🔔 Friend request from ${senderNm} (pubkey: ${senderPk}). Request ID: ${reqId}`;

              if (ownerRoom) {
                await daemonSend(account.url, ownerRoom.id, notifyText);
                ctx.log?.info(`Notified owner about friend request from ${senderNm}`);
              }

              // Also dispatch to agent session so agent has context
              await dispatchToAgent(core, account, normalizePubkey(ownerData.owner), "system", notifyText, ownerRoom?.id, undefined, ctx);
            }
          } catch (err) {
            ctx.log?.error(`Friend request notification failed: ${err}`);
          }
          return;
        }

        // ─── Message handling ──────────────────────────────
        if (eventType !== "message_received" && eventType !== "message") return;
        if (data.kind && data.kind !== "text") return;
        if (!data.sender_pubkey || !data.content) return;

        const sender = normalizePubkey(data.sender_pubkey);
        const senderName = data.sender_name ?? sender.slice(0, 12);
        const roomId = data.room_id;
        const groupId = data.group_id;

        ctx.log?.info(`← [${senderName}] ${data.content.slice(0, 80)}`);
        ctx.setStatus({ lastEventAt: Date.now(), lastInboundAt: Date.now() });

        const cfg = getRuntime().config.loadConfig();
        const currentAccount = resolveAccount(cfg, account.accountId);
        const access = checkAccess(currentAccount, sender);

        if (access === "block") { ctx.log?.info(`Blocked: ${sender.slice(0, 12)}`); return; }
        if (access === "pairing") {
          ctx.log?.info(`Pairing required: ${sender.slice(0, 12)}`);
          try {
            const reply = core.pairing.buildPairingReply({ channel: CHANNEL_ID, senderId: sender, senderName });
            if (roomId) await daemonSend(currentAccount.url, roomId, reply);
          } catch (err) { ctx.log?.error(`Pairing reply failed: ${err}`); }
          return;
        }

        await dispatchToAgent(core, account, sender, senderName, data.content, roomId, groupId, ctx);
      }, ctx.log as any, ctx.abortSignal);

      activeConnections.set(account.accountId, connection);
      const healthTimer = setInterval(() => { ctx.setStatus({ lastEventAt: Date.now() }); }, 20 * 60 * 1000);

      await new Promise<void>((resolve) => {
        ctx.abortSignal.addEventListener("abort", () => {
          connection.stop(); clearInterval(healthTimer);
          activeConnections.delete(account.accountId); resolve();
        });
      });
    },

    stopAccount: async (ctx: ChannelGatewayContext<ResolvedAccount>) => {
      activeConnections.get(ctx.account.accountId)?.stop();
      activeConnections.delete(ctx.account.accountId);
    },
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// Agent dispatch
// ═══════════════════════════════════════════════════════════════════════════

async function dispatchToAgent(
  core: NonNullable<ChannelGatewayContext["channelRuntime"]>,
  account: ResolvedAccount, sender: string, senderName: string,
  text: string, roomId: string | undefined, groupId: string | undefined,
  ctx: { log?: any; setStatus: (s: any) => void },
): Promise<void> {
  const cfg = getRuntime().config.loadConfig();
  const isGroup = !!groupId;
  const peerId = isGroup ? groupId! : sender;
  const peerKind = isGroup ? ("group" as const) : ("direct" as const);

  const route = core.routing.resolveAgentRoute({ cfg, channel: CHANNEL_ID, accountId: account.accountId, peer: { kind: peerKind, id: peerId } });
  const body = core.reply.formatAgentEnvelope({ channel: "Keychat", from: senderName, timestamp: Date.now(), body: text });
  const ctxPayload = core.reply.finalizeInboundContext({
    Body: body, RawBody: text, CommandBody: text, CommandAuthorized: true,
    From: `${CHANNEL_ID}:${sender}`, To: `${CHANNEL_ID}:${account.accountId}`,
    SessionKey: route.sessionKey, AccountId: account.accountId,
    ChatType: peerKind, SenderName: senderName, SenderId: sender,
    Provider: CHANNEL_ID as any, Surface: CHANNEL_ID as any,
    MessageSid: `kc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    OriginatingChannel: CHANNEL_ID as any, OriginatingTo: `${CHANNEL_ID}:${peerId}`,
  });

  const tableMode = core.text.resolveMarkdownTableMode({ cfg, channel: CHANNEL_ID, accountId: account.accountId });
  let deliverBuffer: string[] = [];
  let deliverTimer: ReturnType<typeof setTimeout> | null = null;

  const flush = async () => {
    deliverTimer = null;
    if (deliverBuffer.length === 0) return;
    const merged = deliverBuffer.join("\n\n").trim();
    deliverBuffer = [];
    if (!merged || !roomId) return;
    try {
      await daemonSend(account.url, roomId, merged);
      ctx.setStatus({ lastOutboundAt: Date.now() });
    } catch (err) { ctx.log?.error(`Reply failed: ${err}`); }
  };

  await core.reply.dispatchReplyWithBufferedBlockDispatcher({
    ctx: ctxPayload, cfg,
    dispatcherOptions: {
      deliver: async (payload: { text?: string }) => {
        if (!payload.text) return;
        deliverBuffer.push(core.text.convertMarkdownTables(payload.text, tableMode));
        if (deliverTimer) clearTimeout(deliverTimer);
        deliverTimer = setTimeout(flush, 1500);
      },
      onError: (err: unknown) => { ctx.log?.error(`Dispatch error: ${err}`); },
    },
    replyOptions: {},
  });

  if (deliverTimer) clearTimeout(deliverTimer);
  await flush();
}

// ═══════════════════════════════════════════════════════════════════════════
// Exports for index.ts
// ═══════════════════════════════════════════════════════════════════════════

export function getAllAgentIdentities(): Array<{ accountId: string; npub: string; pubkey_hex: string }> {
  return Array.from(identityCache.entries()).map(([accountId, id]) => ({ accountId, npub: id.npub, pubkey_hex: id.pubkey_hex }));
}

export async function daemonFetchJson(url: string, path: string): Promise<unknown> {
  return daemonJson(url, path);
}

export async function daemonPostJson(url: string, path: string, body: unknown): Promise<unknown> {
  const res = await daemonFetch(url, path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!res.ok) { const text = await res.text().catch(() => ""); throw new Error(`${path} ${res.status}: ${text}`); }
  const json = await res.json() as { ok: boolean; data?: unknown; error?: string };
  if (!json.ok) throw new Error(`${path}: ${json.error ?? "unknown"}`);
  return json.data;
}

export function getResolvedAccount(): { url: string } {
  const cfg = getRuntime().config.loadConfig();
  return resolveAccount(cfg);
}
