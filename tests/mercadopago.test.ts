import { describe, expect, it } from "vitest";
import { computeHmacSha256 } from "../src/core/crypto.js";
import { createSignedRequest, signWebhook } from "../src/testing.js";
import { verifyMercadoPago, verifyWebhook } from "../src/index.js";
import { mercadopagoSigningManifest } from "../src/providers/mercadopago.js";
import { bytesToHex } from "../src/utils/encoding.js";

const secret = "your_secret_key_here";
// Inputs aligned with mercadopago/sdk-nodejs webhook.spec.ts.
const requestId = "2066ca19-c6f1-498a-be75-1923005edd06";
const dataId = "ord01jq4s4ky8hwq6na5pxb65b3d3";
const dataIdUpper = "ORD01JQ4S4KY8HWQ6NA5PXB65B3D3";
const tsSeconds = "1704908010";
const payload = {
  id: 12345,
  live_mode: true,
  type: "payment",
  action: "payment.created",
  data: { id: dataId },
};
const body = JSON.stringify(payload);
const now = 1_704_908_010;

// Pinned digests for secret/requestId above (independent HMAC-SHA256).
const PINNED_LOWER_TS_MS =
  "633f91233312dd391ec75fa0bea539cfc2d6c4918873305b84a96cc1c58db71c";
const PINNED_UPPER_TS_MS =
  "fb15ae6472eb449173c556793205d77787d58f384d183bb5bc3b724c27bd103c";
const tsMs = "1742505638683";

async function manifestV1(
  id: string | undefined,
  rid: string | undefined,
  ts: string,
  key = secret,
) {
  return bytesToHex(
    await computeHmacSha256(key, mercadopagoSigningManifest(id, rid, ts)),
  );
}

async function signedHeaders(
  ts = tsSeconds,
  id = dataId,
  rid: string | undefined = requestId,
  key = secret,
) {
  const v1 = await manifestV1(id, rid, ts, key);
  const headers: Record<string, string> = {
    "x-signature": `ts=${ts},v1=${v1}`,
  };
  if (rid) headers["x-request-id"] = rid;
  return headers;
}

function webhookUrl(id = dataId) {
  return `https://example.com/webhooks/mercadopago?data.id=${encodeURIComponent(id)}`;
}

describe("Mercado Pago", () => {
  it("accepts a valid signature and reads the event", async () => {
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(),
        body,
        url: webhookUrl(),
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
    expect(result.eventType).toBe("payment.created");
  });

  it("verifies pinned SDK-style digests (case preserved)", async () => {
    const [lower, upper] = await Promise.all([
      verifyWebhook(
        "mercadopago",
        {
          headers: {
            "x-signature": `ts=${tsMs},v1=${PINNED_LOWER_TS_MS}`,
            "x-request-id": requestId,
          },
          body,
          url: webhookUrl(dataId),
        },
        secret,
        { tolerance: 0 },
      ),
      verifyWebhook(
        "mercadopago",
        {
          headers: {
            "x-signature": `ts=${tsMs},v1=${PINNED_UPPER_TS_MS}`,
            "x-request-id": requestId,
          },
          body,
          url: webhookUrl(dataIdUpper),
        },
        secret,
        { tolerance: 0 },
      ),
    ]);
    expect(lower.valid).toBe(true);
    expect(upper.valid).toBe(true);
  });

  it("rejects a wrong secret", async () => {
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(tsSeconds, dataId, requestId, "other"),
        body,
        url: webhookUrl(),
      },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("still accepts a modified body (body is not signed)", async () => {
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(),
        body: body.replace("payment.created", "payment.updated"),
        url: webhookUrl(),
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a tampered data.id query value", async () => {
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(),
        body,
        url: webhookUrl("tampered-id"),
      },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects a tampered x-request-id", async () => {
    const result = await verifyMercadoPago(
      {
        headers: {
          ...(await signedHeaders()),
          "x-request-id": "other-request-id",
        },
        body,
        url: webhookUrl(),
      },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("rejects missing and malformed headers", async () => {
    const missing = await verifyMercadoPago(
      { headers: {}, body, url: webhookUrl() },
      secret,
    );
    expect(missing.code).toBe("MISSING_HEADER");

    const malformed = await verifyMercadoPago(
      {
        headers: { "x-signature": "garbage", "x-request-id": requestId },
        body,
        url: webhookUrl(),
      },
      secret,
    );
    expect(malformed.code).toBe("MISSING_HEADER");
  });

  it("rejects expired timestamps unless tolerance is disabled", async () => {
    const headers = await signedHeaders(String(now - 600));
    const req = { headers, body, url: webhookUrl() };
    const expired = await verifyMercadoPago(req, secret, { now });
    expect(expired.code).toBe("EXPIRED_TIMESTAMP");

    const allowed = await verifyMercadoPago(req, secret, {
      now,
      tolerance: 0,
    });
    expect(allowed.valid).toBe(true);
  });

  it("accepts millisecond-shaped timestamps (SDK test vectors)", async () => {
    const ts = String(now * 1000);
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(ts),
        body,
        url: webhookUrl(),
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
    expect(result.timestamp).toBe(now);
  });

  it("omits missing request-id from the manifest", async () => {
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(tsSeconds, dataId, undefined),
        body,
        url: webhookUrl(),
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
  });

  it("omits missing data.id from the manifest", async () => {
    const v1 = await manifestV1(undefined, requestId, tsSeconds);
    const result = await verifyMercadoPago(
      {
        headers: {
          "x-signature": `ts=${tsSeconds},v1=${v1}`,
          "x-request-id": requestId,
        },
        body,
        url: "https://example.com/webhooks/mercadopago",
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
  });

  it("does not treat a plain id query param as data.id", async () => {
    const signedForDataId = await signedHeaders();
    const result = await verifyMercadoPago(
      {
        headers: signedForDataId,
        body,
        url: `https://example.com/webhooks/mercadopago?id=${encodeURIComponent(dataId)}`,
      },
      secret,
      { now },
    );
    expect(result.code).toBe("INVALID_SIGNATURE");
  });

  it("preserves data.id case in the manifest", async () => {
    const result = await verifyMercadoPago(
      {
        headers: await signedHeaders(tsSeconds, dataIdUpper),
        body,
        url: webhookUrl(dataIdUpper),
      },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);

    const mismatched = await verifyMercadoPago(
      {
        headers: await signedHeaders(tsSeconds, dataIdUpper),
        body,
        url: webhookUrl(dataId),
      },
      secret,
      { now },
    );
    expect(mismatched.code).toBe("INVALID_SIGNATURE");
  });

  it("round-trips signWebhook", async () => {
    const hook = await signWebhook("mercadopago", {
      secret,
      payload,
      timestamp: now,
      webhookId: requestId,
    });
    const result = await verifyMercadoPago(
      { headers: hook.headers, body: hook.body, url: hook.url },
      secret,
      { now },
    );
    expect(result.valid).toBe(true);
  });

  it("verifies a Fetch Request (Workers / edge runtime shape)", async () => {
    const request = await createSignedRequest("mercadopago", {
      secret,
      payload,
      timestamp: now,
      webhookId: requestId,
    });
    const result = await verifyWebhook("mercadopago", request, secret, {
      now,
    });
    expect(result.valid).toBe(true);
    expect(result.eventType).toBe("payment.created");
  });
});
