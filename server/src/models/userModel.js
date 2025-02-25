import mongoose from "mongoose";
import crypto from "crypto";

const UserSchema = new mongoose.Schema(
  {
    // Core user information
    email: {
      type: String,
      required: [true, "Email address is required"],
      unique: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: function (v) {
          return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
        },
        message: (props) => `${props.value} is not a valid email address!`,
      },
      index: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters long"],
      select: false, // Don't include password in query results by default
    },
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
    },
    username: {
      type: String,
      required: false,
      unique: true,
      sparse: true, // Allow multiple null values (for optional username)
      trim: true,
      minlength: [3, "Username must be at least 3 characters long"],
      validate: {
        validator: function (v) {
          return /^[a-zA-Z0-9_.-]+$/.test(v);
        },
        message:
          "Username can only contain letters, numbers, underscores, dots and hyphens",
      },
    },

    // Profile information
    profilePicture: {
      type: String,
      default: null,
    },
    phoneNumber: {
      type: String,
      default: null,
      validate: {
        validator: function (v) {
          return !v || /^\+?[1-9]\d{1,14}$/.test(v); // E.164 format validation
        },
        message: "Please provide a valid phone number",
      },
    },

    // Security and verification
    role: {
      type: String,
      enum: ["user", "admin", "editor", "moderator"],
      default: "user",
    },
    permissions: {
      type: [String],
      default: [],
    },
    verified: {
      type: Boolean,
      default: false,
    },
    active: {
      type: Boolean,
      default: true,
    },
    verificationToken: String,
    verificationExpires: Date,
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    refreshToken: String,
    refreshTokens: [
      {
        token: String,
        expires: Date,
        userAgent: String,
        ip: String,
        lastUsed: Date,
      },
    ],

    // Account security
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockedUntil: Date,
    passwordChangedAt: Date,
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    twoFactorSecret: {
      type: String,
      select: false,
    },
    backupCodes: {
      type: [String],
      select: false,
    },

    // Tracking and analytics
    lastLogin: {
      type: Date,
      default: Date.now,
    },

    loginHistory: [
      {
        timestamp: Date,
        ip: String,
        userAgent: String,
        location: String,
        successful: Boolean,
      },
    ],

    // Preferences and settings
    preferences: {
      theme: {
        type: String,
        enum: ["light", "dark", "system"],
        default: "system",
      },
      emailNotifications: {
        type: Boolean,
        default: true,
      },
      language: {
        type: String,
        default: "en",
      },
    },

    // Terms acceptance and GDPR
    termsAccepted: {
      type: Boolean,
      default: false,
    },
    termsAcceptedAt: Date,
    privacyPolicyAccepted: {
      type: Boolean,
      default: false,
    },
    privacyPolicyAcceptedAt: Date,
    dataProcessingConsent: {
      type: Boolean,
      default: false,
    },
    marketingConsent: {
      type: Boolean,
      default: false,
    },

    // Deletion and account management
    deletionRequestedAt: Date,
    deletionScheduledFor: Date,
    deletionReason: String,
    suspendedUntil: Date,
    suspensionReason: String,
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual property for full name (if you want to split name into first/last)
UserSchema.virtual("fullName").get(function () {
  return `${this.firstName || ""} ${this.lastName || ""}`.trim();
});

// Pre-save middleware to update passwordChangedAt on password change
UserSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000; // -1s to ensure token created after password change
  next();
});

// Pre-save middleware to convert email to lowercase
UserSchema.pre("save", function (next) {
  if (this.isModified("email")) {
    this.email = this.email.toLowerCase();
  }
  next();
});

// Static method to check if password was changed after token was issued
UserSchema.methods.changedPasswordAfterToken = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Method to create password reset token
UserSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour

  return resetToken; // Return unhashed token to send via email
};

// Method to create email verification token
UserSchema.methods.createVerificationToken = function () {
  const verificationToken = crypto.randomBytes(32).toString("hex");

  this.verificationToken = verificationToken;
  this.verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  return verificationToken;
};

// Method to verify if user account is active and not locked
UserSchema.methods.isActiveAndUnlocked = function () {
  return this.active && (!this.lockedUntil || this.lockedUntil < Date.now());
};

// Indexes for performance
UserSchema.index({ verificationToken: 1 });
UserSchema.index({ resetPasswordToken: 1 });
UserSchema.index({ "refreshTokens.token": 1 });

const User = mongoose.model("User", UserSchema);

export default User;
