// auth.middleware.js
import jwt from "jsonwebtoken";
import User from "../models/userModel.js";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

/**
 * Middleware to protect routes with JWT authentication
 * Verifies the token and attaches the user to the request object
 */
exports.protect = async (req, res, next) => {
  try {
    let token;

    // Get token from Authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in.",
      });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          success: false,
          message: "Token expired. Please log in again.",
          code: "TOKEN_EXPIRED",
        });
      }

      return res.status(401).json({
        success: false,
        message: "Invalid token. Please log in again.",
      });
    }

    // Check if user exists
    const user = await User.findById(decoded.sub).select("-password");
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found or deactivated",
      });
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({
      success: false,
      message: "Authentication error",
    });
  }
};

/**
 * Middleware to restrict access based on user roles
 * @param {...String} roles - Roles allowed to access the route
 * @returns {Function} Middleware function
 */
exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // Check if user has required role
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "You do not have permission to perform this action",
      });
    }
    next();
  };
};

/**
 * Optional authentication middleware
 * Attaches user to request if token is valid, but doesn't block request if no token or invalid
 */
exports.optionalAuth = async (req, res, next) => {
  try {
    let token;

    // Get token from Authorization header
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    // If no token, continue without authentication
    if (!token) {
      return next();
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      // Continue without authentication if token is invalid
      return next();
    }

    // Check if user exists
    const user = await User.findById(decoded.sub).select("-password");
    if (user) {
      // Attach user to request
      req.user = user;
    }

    next();
  } catch (error) {
    // Continue without authentication on error
    next();
  }
};
