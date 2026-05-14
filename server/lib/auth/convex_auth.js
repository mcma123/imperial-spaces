import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

import { ConvexHttpClient } from "convex/browser";
import { makeFunctionReference } from "convex/server";

import {
  CLIENT_KEY_LABEL,
  PASSWORD_HASH,
  PASSWORD_ITERATIONS,
  PASSWORD_KEY_LENGTH,
  PASSWORD_SCHEME,
  SERVER_KEY_LABEL,
  encodeBase64Url
} from "./passwords.js";

const getLoginVerifierRef = makeFunctionReference("spaceAuth:getLoginVerifier");
const recordLoginRef = makeFunctionReference("spaceAuth:recordLogin");
const upsertPasswordVerifierRef = makeFunctionReference("spaceAuth:upsertPasswordVerifier");

function normalizeConfigValue(value) {
  return String(value || "").trim();
}

function createPublicPasswordVerifier(password, options = {}) {
  const iterations = Number(options.iterations) || PASSWORD_ITERATIONS;
  const salt = options.salt || encodeBase64Url(randomBytes(16));
  const saltedPassword = pbkdf2Sync(
    String(password || ""),
    Buffer.from(salt, "base64url"),
    iterations,
    PASSWORD_KEY_LENGTH,
    PASSWORD_HASH
  );
  const clientKey = createHmac(PASSWORD_HASH, saltedPassword).update(CLIENT_KEY_LABEL).digest();
  const storedKey = createHash(PASSWORD_HASH).update(clientKey).digest();
  const serverKey = createHmac(PASSWORD_HASH, saltedPassword).update(SERVER_KEY_LABEL).digest();

  return {
    iterations,
    passwordScheme: PASSWORD_SCHEME,
    salt,
    serverKey: encodeBase64Url(serverKey),
    storedKey: encodeBase64Url(storedKey)
  };
}

function createConvexAuthBridge(options = {}) {
  const env = options.env || process.env;
  const convexUrl = normalizeConfigValue(env.CONVEX_URL);
  const adminSecret = normalizeConfigValue(env.SPACE_CONVEX_AUTH_SECRET);

  if (!convexUrl || !adminSecret) {
    return null;
  }

  const client = new ConvexHttpClient(convexUrl);

  return {
    async getLoginVerifier(username) {
      return await client.query(getLoginVerifierRef, {
        adminSecret,
        username
      });
    },
    async recordLogin(username) {
      return await client.mutation(recordLoginRef, {
        adminSecret,
        username
      });
    },
    async upsertPasswordUser({ password, username }) {
      return await client.mutation(upsertPasswordVerifierRef, {
        ...createPublicPasswordVerifier(password),
        active: true,
        adminSecret,
        username
      });
    }
  };
}

export { createConvexAuthBridge, createPublicPasswordVerifier };
