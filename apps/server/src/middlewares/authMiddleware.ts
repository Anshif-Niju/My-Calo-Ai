import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

export interface AuthenticatedRequest extends Request {
  user?: any;
}

export const protect = async (req: Request, res: Response, next: NextFunction) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET || "calo_secretKey") as {
        userId: string;
      };

      req.user = { userId: decoded.userId };

      return next();
    } catch (error) {
      console.error("Auth Middleware Error:", error);
      return res.status(401).json({ success: false, message: "Not authorized, token failed!" });
    }
  }

  if (!token) {
    return res.status(401).json({ success: false, message: "Not authorized, no token found!" });
  }
};
