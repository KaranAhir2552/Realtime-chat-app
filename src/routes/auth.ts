import { Router } from "express";
import { signin, signup, verifyEmail } from "../controllers/authController";
import authenticateToken from "../middleware/authenticateToken";

const router = Router();

router.post('/signup',authenticateToken, signup);
router.post('/verify-email', verifyEmail);
router.post('/signin', signin);

export default router;