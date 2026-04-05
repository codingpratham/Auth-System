import type { NextFunction, Request, Response } from "express";
import { prisma } from "../utils/prisma.js";
import rateLimit from "express-rate-limit";

declare module "express" {
  interface Request {
    userId?: number;
  }
}

export const AuthMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const token = req.cookies?.refreshToken;

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const stored = await prisma.refreshToken.findUnique({
      where: { token },
    });

    if (!stored) {
      return res.status(403).json({
        message: "Invalid refresh token",
      });
    }

    req.userId = stored.userId;

    next();
  } catch (error) {
    return res.status(500).json({
      message: "Internal server error",
    });
  }
};

export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts, please try again later",
  standardHeaders: true,
  legacyHeaders: false,
});
