import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import authorizeRouter from "./authorize.route";
import tokenRouter from "./token.route";
import { Application } from "express";

export const app: Application = express();

app.use(express.urlencoded({extended: true}))
app.use(cookieParser())
app.use(cors({
  origin: [],
  credentials: true,
}))

app.use("/", authorizeRouter)
app.use("/", tokenRouter)

app.listen(7890, () => {
  console.log("->> Server is ready", 7890)
})
