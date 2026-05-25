import { UserModel } from "@calo/database";
import bcrypt from "bcrypt";
import { Request, Response, Router } from "express";
import jwt from "jsonwebtoken";
import passport from "passport";
import qrcode from "qrcode";
import speakeasy from "speakeasy";

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || "calo_secretKey";

// 1. SIGNUP ROUTE

router.post("/signup", async (req: Request, res: Response) => {
  try {
    const { name, email, height, weight, targetWeight, fitnessGoal, dailyCalorieTarget, password } =
      req.body;

    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "This email already exists!" });
    }
    if (!password) {
      return res.status(400).json({ message: "Password is required!" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 Minutes expiry

    const newUser = new UserModel({
      name,
      email,
      password: hashedPassword,
      height,
      weight,
      targetWeight,
      fitnessGoal,
      dailyCalorieTarget,
      otp,
      otpExpires,
      isVerified: false,
    });

    await newUser.save();

    console.log(`\n=== [EMAIL SIMULATION] SIGNUP OTP ===`);
    console.log(`Sent to ${email}: ${otp} \n=======================================\n`);

    return res.status(201).json({
      message: "User registered successfully! Please verify your signup OTP.",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
      },
    });
  } catch (error) {
    console.error("Signup Error:", error);
    return res.status(500).json({ message: "Server error, registration failed." });
  }
});

// 2. VERIFY SIGNUP OTP ROUTE

router.post("/verify-otp", async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP!" });
    }

    if (user.otpExpires && new Date() > user.otpExpires) {
      return res.status(400).json({ message: "OTP time expired!" });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    return res.status(200).json({
      message: "Email verified successfully! You can now login.",
    });
  } catch (error) {
    console.error("OTP Verification Error:", error);
    return res.status(500).json({ message: "Server error during verification." });
  }
});

// 3. LOGIN ROUTE

router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid Email or Password!" });
    }

    const isMatch = await bcrypt.compare(password, user.password || "");
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Email or Password!" });
    }

    if (!user.isVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email via OTP before logging in!" });
    }

    const loginOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const loginOtpExpires = new Date(Date.now() + 5 * 60 * 1000); // 5 Minutes expiry

    user.otp = loginOtp;
    user.otpExpires = loginOtpExpires;
    await user.save();

    console.log(`\n=== 🔑 [LOGIN OTP REQUIRED] ===`);
    console.log(`Sent to ${email}: ${loginOtp}\n===============================\n`);

    return res.status(200).json({
      message: "LOGIN_OTP_REQUIRED",
      info: "Verify OTP sent to your email",
    });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ message: "Server error during login." });
  }
});

// 4. VERIFY LOGIN OTP ROUTE

router.post("/verify-login-otp", async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;

    const user = await UserModel.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found!" });

    if (!user.otp || user.otp !== otp) {
      return res.status(400).json({ message: "Invalid Login OTP!" });
    }
    if (user.otpExpires && new Date() > user.otpExpires) {
      return res.status(400).json({ message: "Login OTP Expired!" });
    }

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

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1d" });

    return res.status(200).json({
      message: "Login successful!",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error("Verify Login OTP Error:", error);
    return res.status(500).json({ message: "Server error during login OTP verification." });
  }
});

// 5. SETUP 2-FACTOR AUTHENTICATION

router.post("/setup-2fa", async (req: Request, res: Response) => {
  try {
    const { userId } = req.body;

    const user = await UserModel.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found!" });

    const secret = speakeasy.generateSecret({
      name: `My Calo AI (${user.email})`,
    });

    if (!secret.otpauth_url) {
      return res.status(500).json({ message: "Error generating 2FA authentication URL." });
    }

    const qrCodeImageUrl = await qrcode.toDataURL(secret.otpauth_url);

    user.twoFactorSecret = secret.base32;
    await user.save();

    return res.status(200).json({
      message: "2FA Setup initiated!",
      qrCode: qrCodeImageUrl,
      secret: secret.base32,
    });
  } catch (error) {
    console.error("2FA Setup Error:", error);
    return res.status(500).json({ message: "Server error during 2FA setup." });
  }
});

// 6. ACTIVATE 2-FACTOR AUTHENTICATION (FIRST TIME)

router.post("/activate-2fa", async (req: Request, res: Response) => {
  try {
    const { userId, code } = req.body;

    const user = await UserModel.findById(userId);
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ message: "2FA setup was not initiated for this user." });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: code,
    });

    if (!verified) {
      return res.status(400).json({ message: "Invalid code! Verification failed. Try again." });
    }

    user.isTwoFactorEnabled = true;
    await user.save();

    return res.status(200).json({
      message: "Google Authenticator 2FA activated successfully!",
    });
  } catch (error) {
    console.error("2FA Activation Error:", error);
    return res.status(500).json({ message: "Server error during 2FA activation." });
  }
});

// 7. VERIFY 2-FACTOR AUTHENTICATION (SUBSEQUENT LOGINS)

router.post("/verify-2fa", async (req: Request, res: Response) => {
  try {
    const { userId, twoFactorCode } = req.body;

    const user = await UserModel.findById(userId);
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ message: "User or 2FA setup not found!" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token: twoFactorCode,
    });

    if (!verified) {
      return res.status(400).json({ message: "Invalid Authenticator Code!" });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1d" });

    return res.status(200).json({
      message: "2FA Login successful!",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error("2FA Verification Error:", error);
    return res.status(500).json({ message: "Server error during 2FA login." });
  }
});

// 8. Redirect the user to Google Login Page

router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// 9. Redirect the user to Google Login Page

router.get("/google/callback",passport.authenticate("google", { session: false, failureRedirect: "/login" }),(req: any, res) => {
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET || "calo_secretKey", {
      expiresIn: "7d",
    });

    res.redirect(`http://localhost:3000/oauth-success?token=${token}`);
  },
);

export default router;
