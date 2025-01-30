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
  try {
    await redis.set(
      `refresh_token:${userId}`,
      refreshToken,
      "EX",
      7 * 24 * 60 * 60
    );
  } catch (error) {
    console.error("Error storing refresh token in Redis:", error);
    throw error;
  }
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
export const signup = async (req, res) => {
  const { name, email, password } = req.body;

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
      _id: newUser._id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: error.message });
  }
};

/**
 * ==========================================
 *                LOGIN
 * ==========================================
 */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Check if password is correct
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user._id);

    // Store refresh token in Redis
    await storeRefreshToken(user._id, refreshToken);

    // Set tokens inside cookie
    setCookies(res, accessToken, refreshToken);

    // Send response
    res.status(200).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: `Login Unsuccessful: ${error.message}` });
  }
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
    console.error("Error during logout:", error);
    res.status(500).json({ message: error.message });
  }
};

/**
 * ==========================================
 *    This will refresh the access token
 * ==========================================
 */
export const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const storedToken = await redis.get(`refresh_token:${decoded.userId}`);

    if (storedToken !== refreshToken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Create new access token
    const accessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    res.cookie("accessToken", accessToken, {
      httpOnly: true, // Prevent XSS attacks
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.json({ message: "Token refresh successfully" });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: error.message });
  }
};

// TODO: Implement it later
// export const getProfile = async (req, res) => {};
