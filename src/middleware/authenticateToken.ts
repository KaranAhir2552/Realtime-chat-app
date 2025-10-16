import { NextFunction, Request, Response } from "express";
import jwt from 'jsonwebtoken'
import { JwtPayload } from "../types";
declare global {
  namespace Express {
    interface Request {
      user?: { userId: string };
    }
  }
}

const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const auth = req.get("Authorization");
    const token = auth && auth.startsWith("Bearer ") ? auth.slice(7) : null;

    if (!token) {
      return res.status(401).json({ message: "Please login" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    req.user = { userId: decoded.userId }; // ✅ Attach to req
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

export default authenticateToken;
