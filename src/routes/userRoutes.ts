import { Router } from "express";
import { authenticate, authorizeRole } from "../middleware/authMiddleware";
import { getUserDetails } from "../controllers/userController";

const router = Router();

router.get("/admin", authenticate, authorizeRole("admin"), (req, res) => {
    res.send("Admin Access");
});

router.get("/user", authenticate, getUserDetails);

export default router;
