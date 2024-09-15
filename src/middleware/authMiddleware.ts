import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import RefreshToken from "../models/RefreshToken"; // The schema created above
import crypto from "crypto";
import User from "../models/User";

dotenv.config();

export const authenticate = (
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) return res.status(401).send("Access Denied");

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string);
        (req as any).user = decoded;
        next();
    } catch (error) {
        res.status(400).send("Invalid Token");
    }
};

export const generateAccessToken = (user: any) => {
    return jwt.sign(
        {
            id: user._id,
            username: user.username,
            role: user.role,
        },
        process.env.JWT_SECRET as string,
        { expiresIn: "15m" },
    );
};

export const generateRefreshToken = async (user: any) => {
    const refreshToken = jwt.sign(
        { id: user._id },
        process.env.JWT_REFRESH_SECRET as string,
        { expiresIn: "7d" },
    );
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days expiry
    await new RefreshToken({
        userId: user._id?.toString(),
        token: refreshToken,
        expiresAt,
    }).save();

    return refreshToken;
};

export const authorizeRole =
    (role: string) => (req: Request, res: Response, next: NextFunction) => {
        const user = (req as any).user;
        if (user.role !== role) return res.status(403).send("Access Forbidden");
        next();
    };
