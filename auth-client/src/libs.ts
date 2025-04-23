import axios from "axios";
import config from "./config";
import crypto from "crypto";
import { TokenSet } from "./jwt";
import { Response } from "express";

export function generateNewSession(redis: any, token: TokenSet, res: Response) {
  const sessionId = crypto.randomBytes(32).toString("hex");

  redis.set(`session:${sessionId}`, {
    refresh_token: token.refresh_token,
    access_token: token.access_token,
    expire_at: token.expires_at
  });

  res.cookie(config.clientServer.sessionCookieName, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7day
  });
}

export function codeAuthorize(state: string) {
  const url = new URL(config.authorizationServer.authorizeEndpoint);

  url.searchParams.append("response_type", "code");
  url.searchParams.append("client_id", config.clientId);
  url.searchParams.append("state", state);
  url.searchParams.append("redirect_uri", config.redirectUri);
  url.searchParams.append("code_challenge", config.pkce.code_challenge);
  url.searchParams.append("code_challenge_method", config.pkce.code_challenge_method);

  return url.toString();
}

export async function exchangeCodeForToken(code: string): Promise<TokenSet> {
  const clientCredential = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");
  const response = await axios.post(
    config.authorizationServer.tokenEndpoint,
    {
      code,
      grant_type: "authorization_code",
      redirect_uri: config.redirectUri,
      code_verifier: config.pkce.code_verifier,
    },
    {
      withCredentials: true,
      headers: {
        Authorization: `Basic ${clientCredential}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );

  const now = Math.floor(Date.now() / 1000);
  return {
    access_token: response.data.access_token,
    refresh_token: response.data.refresh_token,
    expires_at: now + (response.data.expires_in / 1000),
    token_type: response.data.token_type,
  };
}

export async function refreshAccessToken(refreshToken: string): Promise<TokenSet> {
  const clientCredential = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");
  const response = await axios.post(
    config.authorizationServer.tokenEndpoint,
    {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      redirect_uri: `http://client-server${config.clientServer.callbackPath}`,
    },
    {
      withCredentials: true,
      headers: {
        Authorization: `Basic ${clientCredential}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );

  const now = Math.floor(Date.now() / 1000);
  return {
    access_token: response.data.access_token,
    refresh_token: response.data.refresh_token,
    expires_at: now + response.data.expires_in,
    token_type: response.data.token_type,
  };
}
