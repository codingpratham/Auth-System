import { Router } from "express";
import {
  Register,
  login,
  refresh,
  logout,
  profile,
  forgetPassword,
  resetPassword,
} from "../controller/authentication.c.js";
import { AuthMiddleware, loginRateLimiter } from "../middlewares/auth.m.js";

const router = Router();

router.post("/register", Register);
router.post("/login", loginRateLimiter, login);
router.post("/refresh", AuthMiddleware, refresh);
router.post("/logout", AuthMiddleware, logout);
router.get("/profile", AuthMiddleware, profile);
router.post("/forget-password", forgetPassword);
router.post("/reset-password", resetPassword);

export default router;
