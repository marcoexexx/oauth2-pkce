import { Router } from "express";
import { clients } from "./db";
import { v4 as uuidv4 } from 'uuid'
import { FakeRedis } from "./fakeRedis";

const router: Router = Router()

router.get("/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;

  if (response_type !== "code") {
    res.status(400).send("EUNSUPPORTED_RESPONSE_TYPE")
    return;
  }

  const client = clients.get(client_id as string);
  if (!client) {
    res.status(400).send("EINVALID_CLIENT");
    return;
  }

  if (!client.redirect_uris.includes(redirect_uri as string)) {
    res.status(400).send("EINVALID_REDIRECT_URI");
    return;
  }

  const code = uuidv4();
  const requestToken = uuidv4();

  // auth code
  FakeRedis.getInstance().set(code, {
    state,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    expires_in: 60 * 15
  })

  FakeRedis.getInstance().set(`request_token:${requestToken}`, { 
    code, 
    client,
    expires_in: 60 * 15 
  })

  res.redirect(`/login?request_token=${requestToken}`);
})

// LOGIN ROUTER
router.get("/login", async (req, res) => {
  const { request_token } = req.query;

  const requestInfo = FakeRedis.getInstance().get<any>(`request_token:${request_token}`);
  if (!requestInfo) {
    res.status(401).json({ message: "session expired" })
    return;
  }

  res.send(`
    <div>
      <p>Wellcome: ${requestInfo.client.client_name}</p>
      <form action="/login" method="post">
        <input hidden type="text" name="request_token" value="${request_token}" />
        <input type="text" name="username" placeholder="username" /></br>
        <input type="password" name="password" placeholder="password" /></br>
        <input type="submit" value="Submit" />
      </form>
    </div>
  `)
})

router.post("/login", async (req, res) => {
  const { username, password, request_token } = req.body;

  if (username !== "demo" || password !== "demo123") {
    res.status(401).json({ message: "wrong credential" })
    return FakeRedis.getInstance().remove(`request_token:${request_token}`)
  }

  const requestToken = FakeRedis.getInstance().get<any>(`request_token:${request_token}`);
  if (!requestToken) {
    res.status(401).json({ message: "session expired" })
    return FakeRedis.getInstance().remove(`request_token:${request_token}`)
  }

  const authCode = FakeRedis.getInstance().get<any>(requestToken.code);
  if (!authCode) {
    res.status(403).send()
    return FakeRedis.getInstance().remove(`request_token:${request_token}`)
  }

  FakeRedis.getInstance().remove(`request_token:${request_token}`)

  const redirectUrl = new URL(authCode.redirect_uri as string);
  redirectUrl.searchParams.set("code", requestToken.code);
  if (authCode.state) redirectUrl.searchParams.set("state", authCode.state as string);
  res.redirect(redirectUrl.toString());
})

export default router;
