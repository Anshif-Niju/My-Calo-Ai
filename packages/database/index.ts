import { IUserProfile } from "@calo/types";
import { Schema, connect, model, models } from "mongoose";

export const connectDB = async (mongoUri: string) => {
  await connect(mongoUri);
  console.log("MongoDB Connected");
};

const UserSchema = new Schema<IUserProfile>({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  height: { type: Number, required: true },
  weight: { type: Number, required: true },
  targetWeight: { type: Number, required: true },
  fitnessGoal: { type: String, enum: ["WEIGHT_LOSS", "WEIGHT_GAIN", "MAINTAIN"], required: true },
  dailyCalorieTarget: { type: Number, required: true },

  otp: { type: String },
  otpExpires: { type: Date },
  isVerified: { type: Boolean, default: false },

  isTwoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String },
});

export const UserModel = models.User || model<IUserProfile>("User", UserSchema);
