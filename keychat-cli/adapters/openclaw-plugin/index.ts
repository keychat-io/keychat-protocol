/**
 * @keychat-io/keychat-cli — OpenClaw channel plugin
 *
 * Thin adapter connecting to keychat-cli agent daemon via HTTP API.
 * No binary, no protocol logic — just SSE in, POST out.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import {
  keychatCliPlugin,
  setRuntime,
  getAllAgentIdentities,
  daemonFetchJson,
  daemonPostJson,
  getResolvedAccount,
  listActiveAccountIds,
  isMultiAccount,
  getAllowFrom,
  patchAllowFrom,
} from "./channel.js";

const CHANNEL_ID = "keychat-cli";

const plugin = {
  id: CHANNEL_ID,
  name: "Keychat CLI",
  description: "E2E encrypted messaging via keychat-cli daemon.",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    setRuntime(api.runtime);
    api.registerChannel({ plugin: keychatCliPlugin });

    // ─── Identity tool ───────────────────────────────────────

    api.registerTool({
      name: "keychat_cli_identity",
      label: "Keychat CLI Identity",
      description: "Get the Keychat CLI agent identity (npub, pubkey).",
      parameters: { type: "object", properties: {}, required: [] },
      async execute() {
        const identities = getAllAgentIdentities();
        if (identities.length === 0) {
          return {
            details: null,
            content: [{ type: "text" as const, text: "No Keychat CLI accounts active." }],
          };
        }
        return {
          details: null,
          content: identities.map((i) => ({
            type: "text" as const,
            text: `Account: ${i.accountId}\nnpub: ${i.npub}\npubkey: ${i.pubkey_hex}`,
          })),
        };
      },
    });

    // ─── Pending friends tool ────────────────────────────────

    api.registerTool({
      name: "keychat_pending_friends",
      label: "Keychat Pending Friends",
      description: "List pending friend requests waiting for owner approval. Optionally specify accountId for multi-account setups.",
      parameters: {
        type: "object",
        properties: {
          accountId: { type: "string", description: "Account ID (optional, defaults to 'default')" },
        },
        required: [],
      },
      async execute({ accountId }: { accountId?: string }) {
        try {
          const account = getResolvedAccount(accountId);
          const path = account.accountId !== "default" || listActiveAccountIds().length > 1
            ? `/agents/${account.accountId}/pending-friends` : "/pending-friends";
          const data = await daemonFetchJson(account.url, path) as any[];
          if (!data || data.length === 0) {
            return { details: null, content: [{ type: "text" as const, text: `[${account.accountId}] No pending friend requests.` }] };
          }
          const text = data
            .map((p: any) => `• ${p.sender_name ?? "unknown"} (${(p.sender_pubkey ?? "").slice(0, 16)}…) — request_id: ${p.request_id}`)
            .join("\n");
          return { details: null, content: [{ type: "text" as const, text: `[${account.accountId}]\n${text}` }] };
        } catch (err) {
          return { details: null, content: [{ type: "text" as const, text: `Error: ${err}` }] };
        }
      },
    });

    // ─── Approve friend tool ─────────────────────────────────

    api.registerTool({
      name: "keychat_approve_friend",
      label: "Keychat Approve Friend",
      description:
        "Approve a pending friend request. Establishes Signal session AND adds sender to allowFrom.",
      parameters: {
        type: "object",
        properties: {
          request_id: { type: "string", description: "Request ID from pending friends list" },
          accountId: { type: "string", description: "Account ID (optional, defaults to 'default')" },
        },
        required: ["request_id"],
      },
      async execute({ request_id, accountId }: { request_id: string; accountId?: string }) {
        try {
          const account = getResolvedAccount(accountId);
          const path = account.accountId !== "default" || listActiveAccountIds().length > 1
            ? `/agents/${account.accountId}/approve-friend` : "/approve-friend";
          const result = await daemonPostJson(account.url, path, { request_id }) as any;
          const senderPubkey = result?.sender_pubkey;

          if (senderPubkey) {
            const cfg = api.runtime.config.loadConfig();
            const currentAllowFrom = getAllowFrom(cfg, account.accountId);
            if (!currentAllowFrom.includes(senderPubkey) && !currentAllowFrom.includes("*")) {
              currentAllowFrom.push(senderPubkey);
              patchAllowFrom(account.accountId, cfg, currentAllowFrom);
            }
          }

          return {
            details: null,
            content: [{ type: "text" as const, text: `[${account.accountId}] Approved. ${senderPubkey ? `Sender ${senderPubkey.slice(0, 16)}… added to allowFrom.` : "Signal session established."}` }],
          };
        } catch (err) {
          return { details: null, content: [{ type: "text" as const, text: `Error: ${err}` }] };
        }
      },
    });

    // ─── Reject friend tool ──────────────────────────────────

    api.registerTool({
      name: "keychat_reject_friend",
      label: "Keychat Reject Friend",
      description: "Reject a pending friend request. No Signal session established.",
      parameters: {
        type: "object",
        properties: {
          request_id: { type: "string", description: "Request ID from pending friends list" },
          accountId: { type: "string", description: "Account ID (optional, defaults to 'default')" },
        },
        required: ["request_id"],
      },
      async execute({ request_id, accountId }: { request_id: string; accountId?: string }) {
        try {
          const account = getResolvedAccount(accountId);
          const path = account.accountId !== "default" || listActiveAccountIds().length > 1
            ? `/agents/${account.accountId}/reject-friend` : "/reject-friend";
          await daemonPostJson(account.url, path, { request_id });
          return { details: null, content: [{ type: "text" as const, text: `[${account.accountId}] Rejected.` }] };
        } catch (err) {
          return { details: null, content: [{ type: "text" as const, text: `Error: ${err}` }] };
        }
      },
    });
  },
};

export default plugin;
