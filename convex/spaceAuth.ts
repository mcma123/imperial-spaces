import { v } from "convex/values";

import { mutation, query } from "./_generated/server";

function requireAdminSecret(providedSecret: string) {
  const configuredSecret = String(process.env.SPACE_CONVEX_AUTH_SECRET || "").trim();

  if (!configuredSecret || providedSecret !== configuredSecret) {
    throw new Error("Unauthorized");
  }
}

export const getLoginVerifier = query({
  args: {
    adminSecret: v.string(),
    username: v.string(),
  },
  handler: async (ctx, args) => {
    requireAdminSecret(args.adminSecret);

    const username = args.username.trim();
    if (!username) {
      return null;
    }

    const user = await ctx.db
      .query("spaceAuthUsers")
      .withIndex("by_username", (q) => q.eq("username", username))
      .unique();

    if (!user || !user.active) {
      return null;
    }

    return {
      iterations: user.iterations,
      passwordScheme: user.passwordScheme,
      salt: user.salt,
      serverKey: user.serverKey,
      storedKey: user.storedKey,
      username: user.username,
    };
  },
});

export const recordLogin = mutation({
  args: {
    adminSecret: v.string(),
    username: v.string(),
  },
  handler: async (ctx, args) => {
    requireAdminSecret(args.adminSecret);

    const username = args.username.trim();
    if (!username) {
      throw new Error("Username is required.");
    }

    const user = await ctx.db
      .query("spaceAuthUsers")
      .withIndex("by_username", (q) => q.eq("username", username))
      .unique();

    if (!user || !user.active) {
      throw new Error("Unknown Convex auth user.");
    }

    await ctx.db.patch(user._id, {
      lastLoginAt: Date.now(),
    });

    return {
      username: user.username,
    };
  },
});

export const upsertPasswordVerifier = mutation({
  args: {
    active: v.optional(v.boolean()),
    adminSecret: v.string(),
    iterations: v.number(),
    passwordScheme: v.literal("scram-sha-256"),
    salt: v.string(),
    serverKey: v.string(),
    storedKey: v.string(),
    username: v.string(),
  },
  handler: async (ctx, args) => {
    requireAdminSecret(args.adminSecret);

    const username = args.username.trim();
    if (!username) {
      throw new Error("Username is required.");
    }

    const now = Date.now();
    const existing = await ctx.db
      .query("spaceAuthUsers")
      .withIndex("by_username", (q) => q.eq("username", username))
      .unique();
    const record = {
      active: args.active ?? true,
      iterations: args.iterations,
      passwordScheme: args.passwordScheme,
      salt: args.salt,
      serverKey: args.serverKey,
      storedKey: args.storedKey,
      updatedAt: now,
      username,
    };

    if (existing) {
      await ctx.db.patch(existing._id, record);
      return {
        id: existing._id,
        username,
      };
    }

    const id = await ctx.db.insert("spaceAuthUsers", {
      ...record,
      createdAt: now,
    });

    return {
      id,
      username,
    };
  },
});

export const createPasswordVerifier = mutation({
  args: {
    active: v.optional(v.boolean()),
    adminSecret: v.string(),
    iterations: v.number(),
    passwordScheme: v.literal("scram-sha-256"),
    salt: v.string(),
    serverKey: v.string(),
    storedKey: v.string(),
    username: v.string(),
  },
  handler: async (ctx, args) => {
    requireAdminSecret(args.adminSecret);

    const username = args.username.trim();
    if (!username) {
      throw new Error("Username is required.");
    }

    const existing = await ctx.db
      .query("spaceAuthUsers")
      .withIndex("by_username", (q) => q.eq("username", username))
      .unique();

    if (existing) {
      throw new Error("User already exists.");
    }

    const now = Date.now();
    const id = await ctx.db.insert("spaceAuthUsers", {
      active: args.active ?? true,
      createdAt: now,
      iterations: args.iterations,
      passwordScheme: args.passwordScheme,
      salt: args.salt,
      serverKey: args.serverKey,
      storedKey: args.storedKey,
      updatedAt: now,
      username,
    });

    return {
      id,
      username,
    };
  },
});
