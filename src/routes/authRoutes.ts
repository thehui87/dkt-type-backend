import { Router } from "express";
import {
    register,
    login,
    refreshToken,
    sendResetPasswordEmail,
    resetPassword,
} from "../controllers/authController";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh-token", refreshToken);

router.post("/forgot-password", sendResetPasswordEmail);
router.post("/reset-password/:token", resetPassword);

export default router;
