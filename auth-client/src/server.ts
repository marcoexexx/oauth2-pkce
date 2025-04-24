import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import config from "./config";
import helmet from "helmet";

import { Application } from "express";
import { v4 as uuidv4 } from "uuid";
import { generateCSRFToken } from "./csrf";
import { codeAuthorize, exchangeCodeForToken, generateNewSession } from "./libs";
import { authorize } from "./middleware/authorize";
import { validateCsrf } from "./middleware/validateCsrf";

const app: Application = express();

app.use(cookieParser());
app.use(helmet())
app.use(express.json())
app.use(cors({
  origin: ["http://localhost:5173"],
  credentials: true,
}));

const fakeRedis = new Map<string, any>();

// MOCK TODOS
const TODOS = new Map<string, any>([
  ["1", {
    id: "1",
    userId: "user123", // INFO: hardcode
    title: "OAuth2.1 flow",
    completed: false,
  }]
])

// ROUTERS

app.get("/todos", authorize(fakeRedis), (_req, res) => {
  res.status(200).json({ results: Array.from(TODOS.values()) });
});

app.post("/todos/:id", validateCsrf(), authorize(fakeRedis), (req, res) => {
  // WARN: need to user input validation, just demo
  const todo = TODOS.get(req.params.id);
  if (!todo) {
    res.status(404).json({ message: "todo not found" })
    return;
  }

  const payload = {
    title: req?.body?.title ?? todo.title,
    completed: req?.body?.completed ?? todo.completed,
  }

  TODOS.set(req.params.id, {
    ...todo,
    ...payload
  })

  res.json({ message: "success" })
})

app.get("/oauth/login", async (req, res) => {
  const { redirect } = req.query;
  const state = uuidv4();

  fakeRedis.set(`auth-req:${state}`, { state, redirect });
  res.redirect(codeAuthorize(state));
});

app.get(config.clientServer.callbackPath, async (req, res) => {
  const { code, state } = req.query;

  if (state !== fakeRedis.get(`auth-req:${state}`).state) {
    res.status(401).json({ error: "EUNAUTHORIZE" });
    return;
  }

  try {
    const redirect = fakeRedis.get(`auth-req:${state}`)?.redirect;
    const token = await exchangeCodeForToken(code as string);

    generateNewSession(fakeRedis, token, res);
    fakeRedis.delete(`auth-req:${state}`);

    res.redirect(`http://localhost:5173${redirect}`);
  } catch (err: any) {
    const url = new URL("http://localhost:5173/error");

    url.searchParams.append("message", err?.message);
    url.searchParams.append("details", err?.response?.data);
    res.redirect(url.toString());
  }
});

app.get("/me", authorize(fakeRedis), async (req, res) => {
  // INFO: if OIDC -> request /oauth/userinfo -> { Authorization: Bearer <access_token> }
  // @ts-ignore
  const sub = req?.context?.session?.sub

  if (!sub) {
    res.status(401).json({ message: "not_authorized" })
    return;
  }

  res.status(200).json({
    userId: sub
  })
})

/**
 * Route handler for generating and sending a CSRF token.
 * 
 * This endpoint generates a CSRF token to protect against Cross-Site Request Forgery (CSRF) attacks.
 * It uses the "double-submit cookie" pattern along with signed tokens to ensure secure and validated token submission from the client.
 */
app.get("/oauth/csrf-token", (_req, res) => {
  const { token, signedToken } = generateCSRFToken();

  res.cookie(config.csrf.csrfCookieName, token, {
    httpOnly: false,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 10
  });

  res.json({ state: `${token}.${signedToken}` });
});

/**
 * Main Application listener
 */
app.listen(config.clientServer.port, () => {
  console.log("Server is ready", config.clientServer.port);
});
