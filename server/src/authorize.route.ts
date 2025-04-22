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
  const requestId = uuidv4();

  // auth code
  FakeRedis.getInstance().set(code, {
    state,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    expirse_in: 60 * 15
  })

  FakeRedis.getInstance().set(`request_info:${requestId}`, { code, expirse_in: 60 * 15 })

  res.send(`
    <form action="/login" method="post">
      <input hidden type="text" name="request_id" value="${requestId}" />
      <input type="text" name="username" placeholder="username" /></br>
      <input type="password" name="password" placeholder="password" /></br>
      <input type="submit" value="Submit" />
    </form>
  `)
})

// LOGIN ROUTER
router.post("/login", async (req, res) => {
  const { username, password, request_id } = req.body;

  if (username !== "demo" || password !== "demo123") {
    res.status(401).send()
    return;
  }

  const requestInfo = FakeRedis.getInstance().get<any>(`request_info:${request_id}`);
  if (!requestInfo) {
    res.status(403).send()
    return;
  }

  const authCode = FakeRedis.getInstance().get<any>(requestInfo.code);
  if (!authCode) {
    res.status(403).send()
    return;
  }

  FakeRedis.getInstance().remove(`request_info:${request_id}`)

  const redirectUrl = new URL(authCode.redirect_uri as string);
  redirectUrl.searchParams.set("code", requestInfo.code);
  if (authCode.state) redirectUrl.searchParams.set("state", authCode.state as string);
  res.redirect(redirectUrl.toString());
})

export default router;
