export interface IUserProfile{
  name: string;
  email: string;
  password: string;
  height: number;
  weight: number;
  targetWeight: number;
  fitnessGoal: 'WEIGHT_LOSS' | 'WEIGHT_GAIN' | 'MAINTAIN';
  dailyCalorieTarget: number;
  otp?:string;
  otpExpires?: Date;
  isVerified: boolean;
  isTwoFactorEnabled: boolean;
  twoFactorSecret?: string;
}
