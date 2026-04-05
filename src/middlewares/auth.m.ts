import type { NextFunction, Request, Response } from "express";
import { prisma } from "../utils/prisma.js";

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
