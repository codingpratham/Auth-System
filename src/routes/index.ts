import Express from "express";
import authRouter from "./auth.r.js";

export const router = Express.Router();

router.use("/auth", authRouter);
