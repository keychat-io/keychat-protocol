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

interface AccountConfig {
  enabled?: boolean;
  url?: string;
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: Array<string | number>;
}

interface ChannelConfig extends AccountConfig {
  /** Multi-account: each key is an accountId with its own config. */
  accounts?: Record<string, AccountConfig>;
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

function isMultiAccount(cfg: any): boolean {
  const cc = getChannelConfig(cfg);
  return !!(cc?.accounts && Object.keys(cc.accounts).length > 0);
}

function resolveAccount(cfg: any, accountId?: string | null): ResolvedAccount {
  const cc = getChannelConfig(cfg) ?? {};
  const id = accountId ?? DEFAULT_ACCOUNT_ID;

  // Multi-account: merge per-account config over top-level defaults
  const acctCfg = cc.accounts && Object.keys(cc.accounts).length > 0
    ? cc.accounts[id]
    : undefined;

  if (acctCfg) {
    return {
      accountId: id,
      enabled: acctCfg.enabled !== false,
      configured: true,
      url: acctCfg.url ?? cc.url ?? DEFAULT_URL,
      dmPolicy: acctCfg.dmPolicy ?? cc.dmPolicy ?? "pairing",
      allowFrom: acctCfg.allowFrom ?? cc.allowFrom ?? [],
    };
  }

  return {
    accountId: id,
    enabled: cc.enabled !== false,
    configured: true,
    url: cc.url ?? DEFAULT_URL,
    dmPolicy: cc.dmPolicy ?? "pairing",
    allowFrom: cc.allowFrom ?? [],
  };
}

function getAllowFrom(cfg: any, accountId: string): string[] {
  if (isMultiAccount(cfg)) {
    return (cfg.channels?.[CHANNEL_ID]?.accounts?.[accountId]?.allowFrom ?? []).map(String);
  }
  return (cfg.channels?.[CHANNEL_ID]?.allowFrom ?? []).map(String);
}

function patchAllowFrom(accountId: string, cfg: any, allowFrom: string[]): void {
  if (isMultiAccount(cfg)) {
    getRuntime().config.patchConfig({ channels: { [CHANNEL_ID]: { accounts: { [accountId]: { allowFrom } } } } });
  } else {
    getRuntime().config.patchConfig({ channels: { [CHANNEL_ID]: { allowFrom } } });
  }
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

async function daemonSend(url: string, roomId: string, text: string, agentId?: string): Promise<void> {
  const path = agentId ? `/agents/${agentId}/send` : "/send";
  const res = await daemonFetch(url, path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ room_id: roomId, text }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${path} ${res.status}: ${body}`);
  }
}

async function fetchIdentity(url: string, agentId?: string): Promise<DaemonIdentity> {
  const path = agentId ? `/agents/${agentId}/identity` : "/identity";
  const data = await daemonJson<{ pubkey_hex: string; npub: string; name?: string }>(url, path);
  return { pubkey_hex: data.pubkey_hex, npub: data.npub, name: data.name };
}

/** Check if daemon is in multi-agent mode */
async function isDaemonMultiAgent(url: string): Promise<boolean> {
  try {
    const res = await daemonFetch(url, "/agents");
    return res.ok;
  } catch { return false; }
}

/** Ensure agent identity exists in daemon; create if missing */
async function ensureAgentIdentity(url: string, agentId: string, log?: any): Promise<DaemonIdentity> {
  try {
    return await fetchIdentity(url, agentId);
  } catch {
    log?.info(`Agent ${agentId} not found, creating...`);
    const data = await daemonJson<{ agent_id: string; npub: string; pubkey_hex: string }>(
      url, `/agents/${agentId}/identity/create`,
    ).catch(async () => {
      // POST endpoint
      const res = await daemonFetch(url, `/agents/${agentId}/identity/create`, { method: "POST" });
      if (!res.ok) throw new Error(`create ${agentId}: ${res.status}`);
      const body = await res.json() as { ok: boolean; data?: any; error?: string };
      if (!body.ok) throw new Error(`create ${agentId}: ${body.error}`);
      return body.data;
    });
    log?.info(`Agent ${agentId} created: ${data.npub}`);
    return { npub: data.npub, pubkey_hex: data.pubkey_hex };
  }
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
  ssePath?: string,
): SseConnection {
  let stopped = false;
  let controller = new AbortController();
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let reconnectMs = 1000;

  async function connect() {
    if (stopped) return;
    try {
      const sseUrl = `${url.replace(/\/+$/, "")}${ssePath || "/events"}`;
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
    listAccountIds: (cfg) => {
      const cc = getChannelConfig(cfg);
      if (!cc || cc.enabled === false) return [];
      if (cc.accounts && Object.keys(cc.accounts).length > 0) {
        return Object.entries(cc.accounts)
          .filter(([_, acct]) => acct.enabled !== false)
          .map(([id]) => id);
      }
      return [DEFAULT_ACCOUNT_ID];
    },
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
    resolveDmPolicy: ({ account }) => {
      const cfg = getRuntime().config.loadConfig();
      const multi = isMultiAccount(cfg);
      const prefix = multi
        ? `channels.${CHANNEL_ID}.accounts.${account.accountId}`
        : `channels.${CHANNEL_ID}`;
      return {
        policy: account.dmPolicy, allowFrom: account.allowFrom ?? [],
        policyPath: `${prefix}.dmPolicy`, allowFromPath: `${prefix}.allowFrom`,
        approveHint: `/approve ${CHANNEL_ID} <pubkey>`, normalizeEntry: normalizePubkey,
      };
    },
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
      const multi = await isDaemonMultiAgent(account.url);
      await daemonSend(account.url, normalizePubkey(to), text ?? "", multi ? account.accountId : undefined);
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
      ctx.log?.info(`[${account.accountId}] Starting keychat-cli (${account.url})`);
      activeConnections.get(account.accountId)?.stop();

      // Auto-install: if daemon is not running, run postinstall to install binary + start daemon
      let daemonReady = false;
      try {
        const res = await daemonFetch(account.url, "/identity");
        daemonReady = res.ok;
      } catch { /* not running */ }

      if (!daemonReady) {
        ctx.log?.info(`[${account.accountId}] Daemon not running, auto-installing...`);
        try {
          const { execFileSync } = await import("node:child_process");
          const { existsSync } = await import("node:fs");
          const { resolve, dirname } = await import("node:path");
          const { fileURLToPath } = await import("node:url");

          // Find postinstall.sh relative to this plugin
          let scriptDir = "";
          try {
            const thisFile = fileURLToPath(import.meta.url);
            scriptDir = resolve(dirname(thisFile), "scripts");
          } catch {
            // Fallback: try known locations
            const candidates = [
              resolve(process.cwd(), "scripts"),
              resolve(process.env.HOME ?? "~", ".openclaw/extensions/keychat-cli/scripts"),
            ];
            for (const c of candidates) {
              if (existsSync(resolve(c, "postinstall.sh"))) { scriptDir = c; break; }
            }
          }

          const postinstallPath = resolve(scriptDir, "postinstall.sh");
          if (existsSync(postinstallPath)) {
            ctx.log?.info(`[${account.accountId}] Running postinstall: ${postinstallPath}`);
            const output = execFileSync("bash", [postinstallPath], {
              timeout: 120000,
              encoding: "utf-8",
              env: { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` },
            });
            ctx.log?.info(`[${account.accountId}] Postinstall complete`);
            // Log npub lines for debugging
            for (const line of output.split("\n")) {
              if (line.includes("npub:") || line.includes("QR_IMAGE:")) {
                ctx.log?.info(`[${account.accountId}] ${line.trim()}`);
              }
            }
          } else {
            ctx.log?.error(`[${account.accountId}] postinstall.sh not found at ${postinstallPath}`);
          }
        } catch (err) {
          ctx.log?.error(`[${account.accountId}] Auto-install failed: ${err}`);
        }
      }

      // Detect if daemon supports multi-agent mode
      const multiAgent = await isDaemonMultiAgent(account.url);
      const agentId = multiAgent ? account.accountId : undefined;

      try {
        let id: DaemonIdentity;
        if (multiAgent) {
          id = await ensureAgentIdentity(account.url, account.accountId, ctx.log);
        } else {
          id = await fetchIdentity(account.url);
        }
        identityCache.set(account.accountId, id);
        ctx.log?.info(`[${account.accountId}] Identity: ${id.npub}`);
        ctx.setStatus({ accountId: account.accountId, publicKey: id.pubkey_hex, running: true, connected: true, lastStartAt: Date.now() });

        // Notify agent about this identity (once per install, using marker file)
        try {
          const { existsSync, writeFileSync, mkdirSync } = await import("node:fs");
          const markerDir = `${process.env.HOME ?? "~"}/.keychat`;
          const markerFile = `${markerDir}/.notified-${account.accountId}`;
          if (!existsSync(markerFile)) {
            const contactUrl = `https://www.keychat.io/u/?k=${id.npub}`;
            const qrPath = `${markerDir}/qr-${account.accountId}.png`;
            const lines = [
              `[Keychat CLI] Agent "${account.accountId}" is online.`,
              `ID: ${id.npub}`,
              existsSync(qrPath) ? `QR: ${qrPath}` : "",
              `Send this agent's ID and QR code to the user who requested the install.`,
            ].filter(Boolean);
            const rt = getRuntime();
            if (rt.enqueueSystemEvent) {
              rt.enqueueSystemEvent(lines.join("\n"), { sessionKey: `agent:main:main`, trusted: true });
              try { rt.requestHeartbeatNow?.(); } catch { /* best effort */ }
              ctx.log?.info(`[${account.accountId}] Identity notification enqueued`);
            }
            mkdirSync(markerDir, { recursive: true });
            writeFileSync(markerFile, new Date().toISOString());
          }
        } catch { /* best effort */ }
      } catch (err) {
        ctx.log?.error(`[${account.accountId}] Identity fetch failed: ${err}`);
        ctx.setStatus({ accountId: account.accountId, running: true, connected: false, lastError: String(err) });
      }

      const core = ctx.channelRuntime;
      if (!core) { ctx.log?.error("channelRuntime unavailable"); return; }

      // SSE: per-agent stream if multi-agent, global stream otherwise
      const ssePath = agentId ? `/agents/${agentId}/events` : "/events";

      const connection = connectSse(account.url, async (eventType, data) => {
        // ─── Friend request handling ───────────────────────
        if (eventType === "friend_request_received" || eventType === "pending_friend_request") {
          const senderPk = data.sender_pubkey ?? "";
          const senderNm = data.sender_name ?? senderPk.slice(0, 16);
          const reqId = data.request_id ?? "";
          ctx.log?.info(`Friend request from ${senderNm} (${senderPk.slice(0, 16)})`);

          try {
            const ownerPath = agentId ? `/agents/${agentId}/owner` : "/owner";
            const ownerData = await daemonJson<{ owner?: string | null }>(account.url, ownerPath);
            // Owner's own request → auto-add to allowFrom
            if (ownerData.owner && normalizePubkey(ownerData.owner) === normalizePubkey(senderPk)) {
              ctx.log?.info(`Owner ${senderNm} auto-added to allowFrom`);
              const cfg = getRuntime().config.loadConfig();
              const currentAllowFrom = getAllowFrom(cfg, account.accountId);
              if (!currentAllowFrom.includes(normalizePubkey(senderPk)) && !currentAllowFrom.includes("*")) {
                currentAllowFrom.push(normalizePubkey(senderPk));
                patchAllowFrom(account.accountId, cfg, currentAllowFrom);
              }
              return;
            }

            // Non-owner → notify owner
            if (ownerData.owner) {
              const roomsPath = agentId ? `/agents/${agentId}/rooms` : "/rooms";
              const rooms = await daemonJson<Array<{ id: string; to_main_pubkey: string; status: string }>>(account.url, roomsPath);
              const ownerRoom = (rooms ?? []).find((r) => r.to_main_pubkey === ownerData.owner && r.status === "enabled");
              const notifyText = `🔔 Friend request from ${senderNm} (pubkey: ${senderPk}). Request ID: ${reqId}`;

              if (ownerRoom) {
                await daemonSend(account.url, ownerRoom.id, notifyText, agentId);
                ctx.log?.info(`Notified owner about friend request from ${senderNm}`);
              }

              // Also dispatch to agent session so agent has context
              await dispatchToAgent(core, account, normalizePubkey(ownerData.owner), "system", notifyText, ownerRoom?.id, undefined, ctx, agentId);
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
            if (roomId) await daemonSend(currentAccount.url, roomId, reply, agentId);
          } catch (err) { ctx.log?.error(`Pairing reply failed: ${err}`); }
          return;
        }

        await dispatchToAgent(core, account, sender, senderName, data.content, roomId, groupId, ctx, agentId);
      }, ctx.log as any, ctx.abortSignal, ssePath);

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
  agentId?: string,
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
      await daemonSend(account.url, roomId, merged, agentId);
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

export function getResolvedAccount(accountId?: string): ResolvedAccount {
  const cfg = getRuntime().config.loadConfig();
  return resolveAccount(cfg, accountId);
}

export function listActiveAccountIds(): string[] {
  const cfg = getRuntime().config.loadConfig();
  const cc = getChannelConfig(cfg);
  if (!cc || cc.enabled === false) return [];
  if (cc.accounts && Object.keys(cc.accounts).length > 0) {
    return Object.entries(cc.accounts)
      .filter(([_, acct]) => acct.enabled !== false)
      .map(([id]) => id);
  }
  return [DEFAULT_ACCOUNT_ID];
}

export { isMultiAccount, getAllowFrom, patchAllowFrom };
