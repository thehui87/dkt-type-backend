import crypto from "crypto";
import User from "../models/User";

export const generateResetToken = async (email: string) => {
    const user = await User.findOne({ email });
    if (!user) {
        throw new Error("User not found");
    }

    const resetToken = crypto.randomBytes(32).toString("hex"); // Generate token
    const resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(resetPasswordExpires);
    await user.save();

    return resetToken;
};
