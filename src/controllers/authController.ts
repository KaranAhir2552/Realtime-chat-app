import { ErrorRequestHandler, Request, Response } from "express";
import { User } from "../models/User";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import jwt from "jsonwebtoken";

export const signup = async (req: Request, res: Response) => {
  try {
    const { email, password, username } = req.body;
    console.log(req.body)
    if (!email || !password || !username) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already registered" });
    }
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = await User.create({
      email,
      password: hashedPassword,
      username,
      isVerified: false,
      verificationToken,
    });
    return res.status(201).json({
      message: "User created. Please verify your email",
      userId: user._id,
    });
  } catch (error: any) {
    if (error.code === 11000) {
      return res
        .status(409)
        .json({ message: "Username or email already taken" });
    }
    console.log(error)
    return res.status(500).json({ message: "Server error" });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ message: "Verification token is required" });
    }

    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(404).json({ message: "Invalid or expired token" });
    }

    user.isVerified = true;
    user.verificationToken = undefined; // clear token
    await user.save();

    return res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verification error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

export const signin = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    if (!user.isVerified) {
      return res.status(401).json({ message: "Please verify email" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const token = jwt.sign(
        {userId: user._id},
        process.env.JWT_SECRET!,
        {expiresIn: '3d'}
    )
    return res.status(200).json({
      message: "User logged in successfully",
      userId: user._id,
      access_token: token
    });
  } catch (error: any) {
    if (error.code === 11000) {
      return res
        .status(409)
        .json({ message: "Username or email already taken" });
    }
    return res.status(500).json({ message: "Server error" });
  }
};
