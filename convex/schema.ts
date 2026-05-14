import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  spaceAuthUsers: defineTable({
    active: v.boolean(),
    createdAt: v.number(),
    iterations: v.number(),
    lastLoginAt: v.optional(v.number()),
    passwordScheme: v.literal("scram-sha-256"),
    salt: v.string(),
    serverKey: v.string(),
    storedKey: v.string(),
    updatedAt: v.number(),
    username: v.string(),
  }).index("by_username", ["username"]),
});
