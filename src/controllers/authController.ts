import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import User from "../models/User";
import {
    generateAccessToken,
    generateRefreshToken,
} from "../middleware/authMiddleware";
import jwt from "jsonwebtoken";
import { generateResetToken } from "../services/resetTokenService";
import { resetPasswordTemplate } from "../services/emailService";

export const register = async (req: Request, res: Response) => {
    const { username, email, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role,
        });
        await newUser.save();
        res.status(201).send("User registered");
    } catch (error) {
        res.status(500).send("Error registering user");
    }
};

export const login = async (req: Request, res: Response) => {
    const { login, password } = req.body;
    console.log(req.body);

    try {
        // const user = await User.findOne({ username });
        const user = await User.findOne({
            $or: [{ username: login }, { email: login }],
        });
        if (!user) return res.status(400).send("User not found");

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).send("Invalid credentials");
        }
        if (user && validPassword) {
            // Generate access token (short-lived)
            const accessToken = generateAccessToken(user);

            // Generate refresh token (long-lived)
            const refreshToken = await generateRefreshToken(user);

            res.status(200).json({ accessToken, refreshToken });
        }
    } catch (error) {
        console.log(error);
        res.status(500).send("Server error");
    }
};

export const refreshToken = async (req: Request, res: Response) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: "No refresh token provided" });
    }

    try {
        // Verify the refresh token
        jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET as string,
            (err: any, user: any) => {
                if (err) {
                    return res
                        .status(403)
                        .json({ message: "Invalid refresh token" });
                }

                // Generate a new access token
                const newAccessToken = generateAccessToken({ user });

                // Send the new access token to the client
                res.json({ accessToken: newAccessToken });
            },
        );
    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
};

export const sendResetPasswordEmail = async (req: Request, res: Response) => {
    const { email } = req.body;

    try {
        const resetToken = await generateResetToken(email);
        await resetPasswordTemplate(email, resetToken);
        res.status(200).send("Password reset email sent");
    } catch (error: any) {
        res.status(400).send(error.message);
    }
};

const updateNewPassword = async (token: string, newPassword: string) => {
    const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }, // Check if token is still valid
    });

    if (!user) {
        throw new Error("Password reset token is invalid or has expired");
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();
};

export const resetPassword = async (req: Request, res: Response) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    try {
        await updateNewPassword(token, newPassword);
        res.status(200).send("Password has been reset");
    } catch (error: any) {
        res.status(400).send(error.message);
    }
};
