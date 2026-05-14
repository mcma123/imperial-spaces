import { createConvexAuthBridge } from "../lib/auth/convex_auth.js";
import { createUserProfile } from "../lib/auth/user_manage.js";
import { runTrackedMutation } from "../runtime/request_mutations.js";

export const allowAnonymous = true;

const MIN_PASSWORD_LENGTH = 8;

function createHttpError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function normalizeSignupUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeSignupPassword(value) {
  return String(value || "");
}

function validateSignupPayload(payload = {}) {
  const username = normalizeSignupUsername(payload.username);
  const password = normalizeSignupPassword(payload.password);
  const fullName = String(payload.fullName || "").trim();

  if (!/^[A-Za-z0-9_.@-]{1,200}$/u.test(username) || !username.includes("@")) {
    throw createHttpError("Enter a valid email address as the username.", 400);
  }

  if (password.length < MIN_PASSWORD_LENGTH) {
    throw createHttpError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`, 400);
  }

  return {
    fullName: fullName || username,
    password,
    username
  };
}

function translateSignupError(error) {
  const message = String(error?.message || "");

  if (message.includes("User already exists")) {
    return createHttpError("User already exists.", 409);
  }

  if (message.includes("Convex auth is not configured")) {
    return createHttpError(message, 503);
  }

  return createHttpError(message || "Signup failed.", Number(error?.statusCode) || 500);
}

export async function post(context) {
  const payload =
    context.body && typeof context.body === "object" && !Buffer.isBuffer(context.body)
      ? context.body
      : {};
  const signup = validateSignupPayload(payload);
  const convexAuth = createConvexAuthBridge();

  if (!convexAuth || typeof convexAuth.createPasswordUser !== "function") {
    throw createHttpError(
      "Convex auth is not configured. Set CONVEX_URL and SPACE_CONVEX_AUTH_SECRET on this server.",
      503
    );
  }

  try {
    await convexAuth.createPasswordUser({
      password: signup.password,
      username: signup.username
    });

    const user = await runTrackedMutation(context, async () =>
      createUserProfile(context.projectRoot, signup.username, {
        fullName: signup.fullName,
        runtimeParams: context.runtimeParams
      })
    );

    return {
      headers: {
        "Cache-Control": "no-store"
      },
      status: 201,
      body: {
        username: user.username
      }
    };
  } catch (error) {
    throw translateSignupError(error);
  }
}
