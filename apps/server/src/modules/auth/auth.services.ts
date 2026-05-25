import { Response } from "express";
import jwt from "jsonwebtoken";

const ACCESS_SECRET = process.env.JWT_SECRET || "calo_access_secret_123";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "calo_refresh_secret_456";

export const generateTokens = (userId: string) => {
  const accessToken = jwt.sign({ userId }, ACCESS_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId }, REFRESH_SECRET, { expiresIn: "7d" });
  return { accessToken, refreshToken };
};

export const sendRefreshTokenCookie = (res: Response, token: string) => {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};
