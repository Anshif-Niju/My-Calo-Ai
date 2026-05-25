import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { UserModel } from "@calo/database";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      callbackURL: process.env.GOOGLE_CALLBACK_URL!,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0].value;
        if (!email) {
          return done(new Error("Not Find Email in Google Account"), undefined);
        }

        let user = await UserModel.findOne({ email });

        //Create New User using google information
        if (!user) {
          user = await UserModel.create({
            name: profile.displayName,
            email: email,
            password: "google-oauth-dummy-password", // Dummy Password
            isVerified: true, // Google Coming Automatic verify
            height: 0,
            weight: 0,
            targetWeight: 0,
            fitnessGoal: "MAINTAIN",
            dailyCalorieTarget: 2000,
          });
        }

        return done(null, user);
      } catch (error) {
        return done(error as Error, undefined);
      }
    }
  )
);
