import { Router } from "express";
import {
  Register,
  login,
  refresh,
  logout,
  profile,
} from "../controller/authentication.c.js";
import { AuthMiddleware } from "../middlewares/auth.m.js";

const router = Router();

router.post("/register", Register);
router.post("/login", login);
router.post("/refresh", AuthMiddleware, refresh);
router.post("/logout", AuthMiddleware, logout);
router.get("/profile", AuthMiddleware, profile);

export default router;
