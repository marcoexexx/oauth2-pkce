import { NextFunction, Request, Response } from "express";
import config from "../config";
import { validateCSRFSignature } from "../csrf";

export function validateCsrf() {
  return (req: Request, res: Response, next: NextFunction) => {
    const tokenHeader = req.headers[config.csrf.csrfHeaderName.toLowerCase()] as string;
    const tokenCookie = req.cookies[config.csrf.csrfCookieName];

    if (!tokenHeader || !tokenCookie) {
      res.status(403).json({ error: "EBADCSRFTOKEN" });
      return;
    }

    const [token, signature] = tokenHeader.split(".");
    if (!validateCSRFSignature(token, signature)) {
      res.status(403).json({ error: "EINVALIDCSRFSIGNATURE" });
      return;
    }

    if (token !== tokenCookie) {
      res.status(403).json({ error: "ESCRFDONOTMATCH" });
      return;
    }

    next();
  };
}
