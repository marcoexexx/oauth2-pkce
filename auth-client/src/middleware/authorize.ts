import config from '../config'

import { NextFunction, Request, Response } from "express";
import { TokenSet, verifyAccessToken } from "../jwt";
import { generateNewSession, refreshAccessToken } from "../libs";

export function authorize(redis: any) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies[config.clientServer.sessionCookieName];

    if (!sessionId) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }

    const token: TokenSet = redis.get(`session:${sessionId}`);
    if (!token) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }

    const now = Math.floor(Date.now() / 1000)
    const needRefresh = token.expires_at - now < config.clientServer.tokenRefreshMargin;

    if (needRefresh) {
      try {
        console.log("EXPRED GENERATE NEW")
        const newToken = await refreshAccessToken(token.refresh_token);
        generateNewSession(redis, newToken, res);

        const payload = await verifyAccessToken(newToken.access_token);
        // @ts-ignore
        req.context = { session: payload }
      } catch (err: any) {
        console.log("FAILED refresh token", err)
        res.status(401).json({ message: err?.message ?? "invalid_token" })
        return
      }

    } else {
      const payload = await verifyAccessToken(token.access_token);
      // @ts-ignore
      req.context = { session: payload }
    }

    next();
  };
}
