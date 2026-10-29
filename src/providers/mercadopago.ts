/**
 * Mercado Pago webhooks.
 *
 * Mercado Pago signs a manifest built from the query string and headers (not
 * the body) with HMAC-SHA256 and sends:
 *   x-signature: ts=<ts>,v1=<hex>
 *   x-request-id: <uuid>
 * Manifest: `id:<data.id>;request-id:<x-request-id>;ts:<ts>;` — omit any pair
 * whose value is missing. Pass `data.id` exactly as received in the query
 * string (the official Node/PHP SDKs do not rewrite case). Whitespace-only
 * values are treated as absent, matching the SDK's `normalise`.
 * https://www.mercadopago.com/developers/en/docs/your-integrations/notifications/webhooks
 * https://github.com/mercadopago/sdk-nodejs/blob/master/docs/webhooks.md
 *
 * QR Code notifications are not signed — do not use this verifier for them.
 */
import { computeHmacSha256, timingSafeEqual } from "../core/crypto.js";
import { readString } from "../core/event.js";
import {
  NormalizedWebhookRequest,
  ProviderVerifier,
  VerificationResult,
  VerifyWebhookOptions,
  WebhookErrorCode,
} from "../core/types.js";
import { bytesToHex } from "../utils/encoding.js";
import { resolveSignedUrl } from "../utils/request-url.js";
import { toEpochSeconds } from "../utils/timestamp.js";

function parseSignatureHeader(
  header: string,
): { ts: string; v1: string } | null {
  let ts = "";
  let v1 = "";
  for (const part of header.split(",")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (!key || !value) continue;
    if (key === "ts") ts = value;
    else if (key === "v1") v1 = value;
  }
  return ts && v1 ? { ts, v1 } : null;
}

/** Manifest string signed by Mercado Pago (also used by `verihook/testing`). */
export function mercadopagoSigningManifest(
  dataId: string | undefined,
  requestId: string | undefined,
  ts: string,
): string {
  let manifest = "";
  if (dataId) manifest += `id:${dataId};`;
  if (requestId) manifest += `request-id:${requestId};`;
  manifest += `ts:${ts};`;
  return manifest;
}

/** Reads query `data.id` from a request URL (relative or absolute). */
export function mercadopagoDataIdFromUrl(
  url: string | undefined,
): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url, "http://localhost");
    const id = parsed.searchParams.get("data.id")?.trim();
    return id || undefined;
  } catch {
    return undefined;
  }
}

export const mercadopagoVerifier: ProviderVerifier = {
  name: "mercadopago",

  // Prefer `action` (e.g. payment.created) over the coarser `type` (payment).
  eventType: (event) =>
    readString(event, "action") ?? readString(event, "type"),

  async verify(
    req: NormalizedWebhookRequest,
    secret: string,
    options?: VerifyWebhookOptions,
  ): Promise<VerificationResult> {
    const signature = req.headers["x-signature"];
    if (!signature) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Missing "x-signature" header',
      };
    }

    const parsed = parseSignatureHeader(signature);
    if (!parsed || !/^\d+$/.test(parsed.ts)) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.MISSING_HEADER,
        reason: 'Invalid "x-signature" format (expected ts=...,v1=...)',
      };
    }

    // Manifest uses the exact ts string. Replay uses epoch seconds:
    // toEpochSeconds treats |ts| > 1e10 as milliseconds (docs/SDK mixed units).
    const timestamp = toEpochSeconds(Number(parsed.ts));
    const tolerance = options?.tolerance ?? 300;
    if (tolerance > 0) {
      const now = toEpochSeconds(options?.now ?? Math.floor(Date.now() / 1000));
      if (Math.abs(now - timestamp) > tolerance) {
        return {
          valid: false,
          provider: "mercadopago",
          code: WebhookErrorCode.EXPIRED_TIMESTAMP,
          timestamp,
          reason: `Timestamp outside tolerance window (timestamp: ${timestamp}, current: ${now}, tolerance: ${tolerance}s)`,
        };
      }
    }

    const requestId = req.headers["x-request-id"]?.trim() || undefined;
    const dataId = mercadopagoDataIdFromUrl(
      resolveSignedUrl(req, options?.url),
    );
    const expected = bytesToHex(
      await computeHmacSha256(
        secret,
        mercadopagoSigningManifest(dataId, requestId, parsed.ts),
      ),
    );

    if (!timingSafeEqual(parsed.v1.trim().toLowerCase(), expected)) {
      return {
        valid: false,
        provider: "mercadopago",
        code: WebhookErrorCode.INVALID_SIGNATURE,
        timestamp,
        reason: "Signature mismatch",
      };
    }

    return { valid: true, provider: "mercadopago", timestamp };
  },
};
