import { Request, Response } from "express";
import User from "../models/User";

// Controller to get user details from the request
export const getUserDetails = async (req: Request, res: Response) => {
    const resData = (req as any).user; // Access the decoded user info from the request

    // console.log({ user });
    const user = await User.findById(resData.id);
    //   const user = await User.findOne({
    //     $or: [{ username: login }, { email: login }],
    // });
    console.log(user);
    if (!user) return res.status(400).send("User not found");

    if (!user) {
        return res.status(400).json({ message: "No user information found" });
    }

    // Return user details (excluding sensitive data like password)
    res.status(200).json({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
    });
};
