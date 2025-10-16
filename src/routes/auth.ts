import { Router } from "express";
import { getMe, signin, signup, verifyEmail } from "../controllers/authController";
import authenticateToken from "../middleware/authenticateToken";

const router = Router();

router.post('/signup', signup);
router.post('/verify-email', verifyEmail);
router.post('/signin', signin);
router.post('/me',authenticateToken, getMe);

export default router;