import { Router } from "express";
import passport from "passport";
import { protect } from "../../middlewares/authMiddleware";
import {
  signup, verifyOtp, login, verifyLoginOtp, setup2FA,
  activate2FA, verify2FA, handleRefreshToken, handleGoogleCallback, getUserProfile
} from "./auth.controller";

const router = Router();

// Email Auth Routes
router.post("/signup", signup);
router.post("/verify-otp", verifyOtp);
router.post("/login", login);
router.post("/verify-login-otp", verifyLoginOtp);

//  2-Factor Authentication Routes
router.post("/setup-2fa", setup2FA);
router.post("/activate-2fa", activate2FA);
router.post("/verify-2fa", verify2FA);

//  Silent Token Refresh Route
router.post("/refresh", handleRefreshToken);

//  Google OAuth Routes
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"], session: false }));
router.get("/google/callback", passport.authenticate("google", { session: false, failureRedirect: "http://localhost:3000/login" }), handleGoogleCallback as any);

//  Protected User Route

router.get("/me", protect as any, getUserProfile);

export default router;
