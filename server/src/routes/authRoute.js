// auth.routes.js
import express from "express";
import { check, body } from "express-validator";
import authController from "../controllers/authController.js";
import authMiddleware from "../middleware/authMiddleware.js";

const router = express.Router();

/**
 * Input validation middleware
 */
const registerValidation = [
  check("email")
    .isEmail()
    .withMessage("Please include a valid email")
    .normalizeEmail({ gmail_remove_dots: false }),
  check("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .withMessage(
      "Password must contain at least one number, one uppercase letter, one lowercase letter, and one special character"
    ),
  check("name")
    .trim()
    .not()
    .isEmpty()
    .withMessage("Name is required")
    .isLength({ max: 100 })
    .withMessage("Name must be less than 100 characters"),
  check("username")
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters")
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage(
      "Username can only contain letters, numbers, underscores, dots and hyphens"
    ),
];

const loginValidation = [
  check("email")
    .isEmail()
    .withMessage("Please include a valid email")
    .normalizeEmail({ gmail_remove_dots: false }),
  check("password").not().isEmpty().withMessage("Password is required"),
];

const resetPasswordValidation = [
  check("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 8 characters")
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .withMessage(
      "Password must contain at least one number, one uppercase letter, one lowercase letter, and one special character"
    ),
  check("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Password confirmation does not match password");
    }
    return true;
  }),
];

const changePasswordValidation = [
  check("currentPassword")
    .not()
    .isEmpty()
    .withMessage("Current password is required"),
  check("newPassword")
    .isLength({ min: 8 })
    .withMessage("New password must be at least 8 characters")
    .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
    .withMessage(
      "New password must contain at least one number, one uppercase letter, one lowercase letter, and one special character"
    )
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error("New password cannot be the same as current password");
      }
      return true;
    }),
  check("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.newPassword) {
      throw new Error("Password confirmation does not match new password");
    }
    return true;
  }),
];

const updateProfileValidation = [
  check("email")
    .optional()
    .isEmail()
    .withMessage("Please include a valid email")
    .normalizeEmail({ gmail_remove_dots: false }),
  check("name")
    .optional()
    .trim()
    .not()
    .isEmpty()
    .withMessage("Name cannot be empty if provided")
    .isLength({ max: 100 })
    .withMessage("Name must be less than 100 characters"),
  check("username")
    .optional()
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage("Username must be between 3 and 30 characters")
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage(
      "Username can only contain letters, numbers, underscores, dots and hyphens"
    ),
  check("phoneNumber")
    .optional()
    .matches(/^\+?[1-9]\d{1,14}$/)
    .withMessage("Please provide a valid phone number"),
  check("bio")
    .optional()
    .isLength({ max: 500 })
    .withMessage("Bio cannot be more than 500 characters"),
];

const forgotPasswordValidation = [
  check("email")
    .isEmail()
    .withMessage("Please include a valid email")
    .normalizeEmail({ gmail_remove_dots: false }),
];

/**
 * Public routes (no authentication required)
 */
router.post("/register", registerValidation, authController.register);
router.post("/login", loginValidation, authController.login);
router.post("/refresh-token", authController.refreshToken);
router.post("/logout", authController.logout);
router.get("/verify-email/:token", authController.verifyEmail);
router.post(
  "/forgot-password",
  forgotPasswordValidation,
  authController.forgotPassword
);
router.post(
  "/reset-password/:token",
  resetPasswordValidation,
  authController.resetPassword
);

/**
 * Protected routes (authentication required)
 */
router.get("/me", authMiddleware.protect, authController.getMe);

router.put(
  "/change-password",
  authMiddleware.protect,
  changePasswordValidation,
  authController.changePassword
);

/**
 * Admin-only routes
 */
// TODO: Implement admin-only routes
export default router;
