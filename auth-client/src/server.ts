import axios from "axios";
import crypto from "crypto";
import jwt, { JwtHeader, SigningKeyCallback } from "jsonwebtoken";
import express, { NextFunction, Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { Application } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { JwksClient } from "jwks-rsa";
import { validateCsrf } from "./middleware/validateCsrf";
import { generateCSRFToken } from "./csrf";

const CLIENT_ID = "demo-client"
const CLIENT_SECRET = "123"
const AUTHORIZATION_URL = "http://localhost:7890/authorize"
const JWKS_ENDPOINT = "http://localhost:7890/.well-known/jwks.json"
const TOKEN_ENDPOINT = "http://localhost:7890/token"
const REDIRECT_URI = "http://localhost:7891/oauth/callback/chordstack"

const app: Application = express();

app.use(cookieParser())
app.use(cors())

const fakeRedis = new Map<string, any>();

const client = new JwksClient({
  jwksUri: JWKS_ENDPOINT
});

function getKey(header: JwtHeader, callback: SigningKeyCallback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (!key) return callback(err)
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function tokenResolve() {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(" ")[1]
      ?? req.query.access_token as string // WARN: for demo only
    if (!token) {
      res.status(401).json({ message: "No authorized" })
      return;
    }
    jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
      if (err || !decoded) {
        res.status(401).json({ message: "no authorize", details: err?.message })
        return;
      }
      // @ts-ignore
      req.session.userId = decoded.sub as string
      next()
    })
  }
}

app.get("/todos", tokenResolve(), (req, res) => {
  // @ts-ignore
  res.status(200).json({ message: `hello, ${req.session.userId}` })
})

app.get("/oauth/login", async (req, res) => {
  const { redirect } = req.query
  const state = uuidv4();

  fakeRedis.set(`auth-req:${state}`, {state, redirect});

  const params = {
    state,
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code_challenge: "JGMoIeQJqka1vqnIcPDi9YgGYWBPNQKa_ZFlqu33IIQ",
    code_challenge_method: "S256"
  };

  const queryString = new URLSearchParams(params).toString();
  res.redirect(`${AUTHORIZATION_URL}?${queryString}`);
})

app.get("/oauth/callback/chordstack", async (req, res) => {
  const { code, state } = req.query;

  if (state !== fakeRedis.get(`auth-req:${state}`).state) {
    res.status(401).json({ error: "EUNAUTHORIZE" })
    return;
  }

  const clientCredential = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")

  try {
    const { data } = await axios.get(TOKEN_ENDPOINT, {
      params: {
        grant_type: "authorization_code", 
        client_id: CLIENT_ID, 
        client_secret: CLIENT_SECRET, 
        redirect_uri: REDIRECT_URI, 
        code_verifier: "N0NhM0tncXhpc3h6b0ViS2w0eHRQVnFBOUtYYUtaZHc",
        code
      },
      withCredentials: true,
      headers: {
        Authorization: `Basic ${clientCredential}`
      }
    })

    const redirect = fakeRedis.get(`auth-req:${state}`)?.redirect;
    const { refresh_token } = data;

    const sessionId = crypto.randomBytes(32).toString("hex");

    fakeRedis.delete(`auth-req:${state}`)
    fakeRedis.set(`session:${sessionId}`, {
      refresh_token,
      expire_at: Date.now() + 1000 * 60 * 15
    })

    res.cookie("_session", sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/oauth/token",
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7day
    })

    res.redirect(`http://localhost:5173${redirect}`)
  } catch (err: any) {
    res.status(401).json({ error: "failed_auth", details: err?.response?.data, message: err?.message })
  }
})

app.get("/csrf-token", (_req, res) => {
  const { token, signedToken } = generateCSRFToken();

  res.cookie("xsrf-token", token, {
    httpOnly: false,
    secure: true,
    sameSite: "strict",
  });

  res.json({ state: `${token}.${signedToken}` });
});


app.post("/oauth/token", validateCsrf(), async (req, res) => {
  const sessionId = req.cookies._session;

  if (!sessionId) {
    res.status(401).json({ message: "invalid_request" })
    return;
  }

  const session = fakeRedis.get(`session:${sessionId}`)
  if (!session || session.refresh_token) {
    res.status(401).json({ message: "session expired" })
    return;
  }
})

app.listen(7891, () => {
  console.log("Server is ready", 7891)
})
