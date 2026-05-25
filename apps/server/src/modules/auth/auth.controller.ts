import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import qrcode from "qrcode";
import { UserModel } from "@calo/database";
import { generateTokens, sendRefreshTokenCookie } from "./auth.services";

// 1. SIGNUP

export const signup = async (req: Request, res: Response) => {
  try {
    const { name, email, height, weight, targetWeight, fitnessGoal, dailyCalorieTarget, password } = req.body;

    const existingUser = await UserModel.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "This email already exists!" });
    if (!password) return res.status(400).json({ message: "Password is required!" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    const newUser = new UserModel({
      name, email, password: hashedPassword, height, weight, targetWeight, fitnessGoal, dailyCalorieTarget,
      otp, otpExpires, isVerified: false,
    });

    await newUser.save();
    console.log(`\n=== [EMAIL SIMULATION] SIGNUP OTP ===\nSent to ${email}: ${otp}\n=====================================\n`);

    return res.status(201).json({
      message: "User registered successfully! Please verify your signup OTP.",
      user: { id: newUser._id, name: newUser.name, email: newUser.email },
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error, registration failed." });
  }
};

// 2. VERIFY SIGNUP OTP

export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;
    const user = await UserModel.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found!" });
    if (!user.otp || user.otp !== otp) return res.status(400).json({ message: "Invalid OTP!" });
    if (user.otpExpires && new Date() > user.otpExpires) return res.status(400).json({ message: "OTP time expired!" });

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    return res.status(200).json({ message: "Email verified successfully! You can now login." });
  } catch (error) {
    return res.status(500).json({ message: "Server error during verification." });
  }
};

// 3. LOGIN

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await UserModel.findOne({ email });

    if (!user) return res.status(400).json({ message: "Invalid Email or Password!" });

    const isMatch = await bcrypt.compare(password, user.password || "");
    if (!isMatch) return res.status(400).json({ message: "Invalid Email or Password!" });

    if (!user.isVerified) return res.status(403).json({ message: "Please verify your email via OTP before logging in!" });

    const loginOtp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = loginOtp;
    user.otpExpires = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();

    console.log(`\n=== 🔑 [LOGIN OTP REQUIRED] ===\nSent to ${email}: ${loginOtp}\n===============================\n`);
    return res.status(200).json({ message: "LOGIN_OTP_REQUIRED", info: "Verify OTP sent to your email" });
  } catch (error) {
    return res.status(500).json({ message: "Server error during login." });
  }
};

// 4. VERIFY LOGIN OTP

export const verifyLoginOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;
    const user = await UserModel.findOne({ email });

    if (!user) return res.status(404).json({ message: "User not found!" });
    if (!user.otp || user.otp !== otp) return res.status(400).json({ message: "Invalid Login OTP!" });
    if (user.otpExpires && new Date() > user.otpExpires) return res.status(400).json({ message: "Login OTP Expired!" });

    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    if (user.isTwoFactorEnabled) {
      return res.status(200).json({
        message: "2FA_REQUIRED",
        userId: user._id,
        info: "Login OTP verified successfully! Google Authenticator Code Required.",
      });
    }

    const tokens = generateTokens(user._id.toString());
    sendRefreshTokenCookie(res, tokens.refreshToken);

    return res.status(200).json({
      message: "Login successful!",
      accessToken: tokens.accessToken,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error during login OTP verification." });
  }
};

// 5. SETUP 2FA
export const setup2FA = async (req: Request, res: Response) => {
  try {
    const { userId } = req.body;
    const user = await UserModel.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found!" });

    const secret = speakeasy.generateSecret({ name: `My Calo AI (${user.email})` });
    if (!secret.otpauth_url) return res.status(500).json({ message: "Error generating 2FA URL." });

    const qrCodeImageUrl = await qrcode.toDataURL(secret.otpauth_url);
    user.twoFactorSecret = secret.base32;
    await user.save();

    return res.status(200).json({ message: "2FA Setup initiated!", qrCode: qrCodeImageUrl, secret: secret.base32 });
  } catch (error) {
    return res.status(500).json({ message: "Server error during 2FA setup." });
  }
};

// 6. ACTIVATE 2FA
export const activate2FA = async (req: Request, res: Response) => {
  try {
    const { userId, code } = req.body;
    const user = await UserModel.findById(userId);

    if (!user || !user.twoFactorSecret) return res.status(400).json({ message: "2FA setup not initiated." });

    const verified = speakeasy.totp.verify({ secret: user.twoFactorSecret, encoding: "base32", token: code });
    if (!verified) return res.status(400).json({ message: "Invalid code! Verification failed." });

    user.isTwoFactorEnabled = true;
    await user.save();

    return res.status(200).json({ message: "Google Authenticator 2FA activated successfully!" });
  } catch (error) {
    return res.status(500).json({ message: "Server error during 2FA activation." });
  }
};

// 7. VERIFY 2FA (LOGINS)
export const verify2FA = async (req: Request, res: Response) => {
  try {
    const { userId, twoFactorCode } = req.body;
    const user = await UserModel.findById(userId);

    if (!user || !user.twoFactorSecret) return res.status(400).json({ message: "User or 2FA not found!" });

    const verified = speakeasy.totp.verify({ secret: user.twoFactorSecret, encoding: "base32", token: twoFactorCode });
    if (!verified) return res.status(400).json({ message: "Invalid Authenticator Code!" });

    const tokens = generateTokens(user._id.toString());
    sendRefreshTokenCookie(res, tokens.refreshToken);

    return res.status(200).json({
      message: "2FA Login successful!",
      accessToken: tokens.accessToken,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error during 2FA login." });
  }
};

//  8. SILENT REFRESH CONTROLLER
export const handleRefreshToken = async (req: Request, res: Response) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ success: false, message: "Refresh Token Missing!" });

    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET || "calo_refresh_secret_456") as { userId: string };
    const tokens = generateTokens(decoded.userId);
    sendRefreshTokenCookie(res, tokens.refreshToken);

    return res.status(200).json({ success: true, accessToken: tokens.accessToken });
  } catch (error) {
    return res.status(403).json({ success: false, message: "Invalid or Expired Refresh Token!" });
  }
};

//  9. GOOGLE OAUTH CALLBACK
export const handleGoogleCallback = async (req: any, res: Response) => {
  try {
    if (!req.user) return res.redirect("http://localhost:3000/login?error=auth_failed");

    const tokens = generateTokens(req.user._id.toString());
    sendRefreshTokenCookie(res, tokens.refreshToken);

    return res.redirect(`http://localhost:3000/oauth-success?token=${tokens.accessToken}`);
  } catch (error) {
    return res.redirect("http://localhost:3000/login?error=server_error");
  }
};

//  10. GET PROFILE
export const getUserProfile = async (req: any, res: Response) => {
  try {
    const user = await UserModel.findById(req.user?.userId).select("-password");
    if (!user) return res.status(404).json({ success: false, message: "User not found!" });
    return res.status(200).json({ success: true, user });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Server Error!" });
  }
};
