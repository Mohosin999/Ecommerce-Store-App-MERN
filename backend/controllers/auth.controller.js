import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { redis } from "../lib/redis.js";

dotenv.config();

/**
 * Generates access and refresh tokens for a given user ID.
 *
 * @param {string} userId - The ID of the user for whom the tokens are being generated.
 * @returns {Object} An object containing the accessToken and refreshToken.
 */
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

/**
 * Stores a refresh token in Redis for a given user ID.
 *
 * @param {string} userId - The ID of the user for whom the refresh token is being stored.
 * @param {string} refreshToken - The refresh token to store.
 * @returns {Promise<void>} A promise that resolves when the token is successfully stored.
 */
const storeRefreshToken = async (userId, refreshToken) => {
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60
  );
};

/**
 * Sets access and refresh tokens as HTTP-only cookies in the response.
 *
 * @param {Object} res - The response object to set the cookies on.
 * @param {string} accessToken - The access token to set in the cookie.
 * @param {string} refreshToken - The refresh token to set in the cookie.
 * @returns {void}
 */
const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true, // Prevent XSS attacks
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, // Prevent XSS attacks
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

/**
 * ==========================================
 *                SIGNUP
 * ==========================================
 */
export const signup = async (_req, res) => {
  const { name, email, password } = _req.body;

  try {
    // Check if user already exists
    const user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Create new user
    const newUser = await User.create({ name, email, password });

    // Authenticate user
    const { accessToken, refreshToken } = generateTokens(newUser._id);
    await storeRefreshToken(newUser._id, refreshToken);

    // Set tokens inside cookie
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      newUser: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
      },
      message: "User created successfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

/**
 * ==========================================
 *                LOGIN
 * ==========================================
 */
export const login = async (_req, res) => {
  res.send("Login route called");
};

/**
 * ==========================================
 *                LOGOUT
 * ==========================================
 */
export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      const decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      await redis.del(`refresh_token:${decoded.userId}`);
    }

    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
