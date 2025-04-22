import axios from "axios";
import express from "express";
import { v4 as uuidv4 } from "uuid";
import { Application } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

const CLIENT_ID = "demo-client"
const CLIENT_SECRET = "123"
const AUTHORIZATION_URL = "http://localhost:7890/authorize"
const TOKEN_ENDPOINT = "http://localhost:7890/token"
const REDIRECT_URI = "http://localhost:7891/oauth/callback/chordstack"

const app: Application = express();

app.use(cookieParser())
app.use(cors({
  origin: ["http://localhost:7890"],
  credentials: true
}))

const fakeRedis = new Map<string, any>();

app.get("/oauth/login", async (_req, res) => {
  const state = uuidv4();

  fakeRedis.set(`auth-req:${state}`, state);

  const params = {
    state,
    response_type: 'code',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    code_challenge: "JGMoIeQJqka1vqnIcPDi9YgGYWBPNQKa_ZFlqu33IIQ",
    code_challenge_method: "S256"
  };

  const queryString = new URLSearchParams(params).toString();
  res.redirect(`${AUTHORIZATION_URL}?${queryString}`);
})

app.get("/oauth/callback/chordstack", async (req, res) => {
  const { code, state } = req.query;

  if (state !== fakeRedis.get(`auth-req:${state}`)) {
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

    const { access_token, refresh_token } = data;

    fakeRedis.delete(`auth-req:${state}`)
    res.status(200).json({ access_token, refresh_token })
  } catch (err: any) {
    res.status(401).json({ error: "failed_auth", details: err?.response?.data })
  }
})


app.listen(7891, () => {
  console.log("Server is ready", 7891)
})
