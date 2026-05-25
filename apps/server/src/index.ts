import dotenv from "dotenv";
dotenv.config();
import express, { Request, Response } from "express";
import cors from "cors";
import passport from "passport";
import { connectDB } from "@calo/database";
import "./config/passport";
import authRoutes from "./routes/auth";


const app = express();
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

app.use("/api/auth", authRoutes);

const startServer = async () => {
  try {
    await connectDB(process.env.MONGO_URI || "");
    console.log("Database connected successfully via Monorepo!");

    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
      console.log(`Express API Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start the server:", error);
  }
};

app.get("/health", (_req: Request, res: Response) => {
  res.send({ status: "Server is running perfectly!" });
});

startServer();
