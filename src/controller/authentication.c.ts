import type { Request, Response } from "express";
import { prisma } from "../utils/prisma.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const Register = async (req: Request, res: Response): Promise<void> => {
  const { email, password, name } = req.body;

  if (email || password || name) {
    res.status(411).json({
      message: "input field is missing",
    });
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (existingUser) {
      res.status(411).json({
        message: "user is already exist",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const user = await prisma.user.create({
      data: {
        name: name,
        email: email,
        password: hashed,
      },
    });

    const token = jwt.sign(user.id as any, process.env.JWT_SECRET as any, {
      expiresIn: "15min",
    });

    if (user) {
      res.status(200).json({
        message: "User successfully created",
        user: user,
        token: token,
      });
    }
  } catch (error: any) {
    console.log(error);
    res.status(404).json({
      message: "Register controller is out",
    });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  if (email || password) {
    res.status(411).json({
      message: "input field is missing",
    });
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!existingUser) {
      res.status(401).json({
        message: "User not found",
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      existingUser?.password as string,
    );

    if (!isMatch) {
      res.status(401).json({ message: "Invalid credentials" });
    }

    res.status(200).json({
      message: "user loggin in successfully",
    });
  } catch (error: any) {
    console.log(error);
    res.status(404).json({
      message: "Register controller is out",
    });
  }
};
