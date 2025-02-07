import { jwt } from "jsonwebtoken";
import User from "./../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    const acccessToken = req.cookies.accessToken;

    if (!acccessToken) {
      return res
        .status(401)
        .json({ message: "Unauthorized - No access token" });
    }

    try {
      const decoded = jwt.verify(acccessToken, process.env.ACCESS_TOKEN_SECRET);
      const user = await User.findById(decoded.userId).select("-password");

      if (!user) {
        return res
          .status(401)
          .json({ message: "Unauthorized - User not found" });
      }

      req.user = user;

      next();
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ message: "Unauthorized - User not found" });
      }
      throw error;
    }
  } catch (error) {
    console.log("Error in protectRoute middleware", error.message);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const adminRoute = (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    return res.status(403).json({ message: "Access denied - Admin only" });
  }
};
