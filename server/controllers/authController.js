import UserModel from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";

export const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const existingUser = await UserModel.findOne({ email });

    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new UserModel({ name, email, password: hashedPassword });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //Sending welcome email

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: "welcome to Advance Auth",
      text: `Hello ${name}, welcome to Advance Auth. We're glad to have you with us.Your account has been created with email: ${email}`,
    };

    await transporter.sendMail(mailOptions);

    return res.json({ success: true, message: "Registered successfully" });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("token", token, {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json({ success: true, message: "LoggedIn successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,

      secure: process.env.NODE_ENV === "production",

      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    });

    return res.json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//Sending verification OTP to users's email
export const sendVerifyOtp = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await UserModel.findById(userId);

    if (user.isAccountVerified) {
      return res.json({ success: true, message: "Account already verified" });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Verify your email",
      text: `Your verification OTP is ${otp}`,
    };

    await transporter.sendMail(mailOption);

    res.json({ success: true, message: "Verification OTP sent successfully" });
  } catch (error) {
    return res.json({ success: true, message: error.message });
  }
};

//Verify email using otp
export const verifyEmail = async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const user = await UserModel.findById(userId);

    if (!user) {
      return res.json({ success: false, message: "User does not exist" });
    }

    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;

    await user.save();
    return res.json({ success: true, message: "Email verfied successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//Checks if user is authenticated
export const isAuthenticated = async (req, res) => {
  try {
    return res.json({ success: true, message: "authenticated" });
  } catch (error) {
    return res.json({ success: true, message: error.message });
  }
};

//Send user resetOtp
export const sendResetOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }

    try {
      const user = await UserModel.findOne({ email });

      if (!email) {
        return res.json({ success: false, message: "User does not exist" });
      }

      const otp = String(Math.floor(100000 + Math.random() * 900000));

      user.resetOtp = otp;
      user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

      await user.save();

      const mailOption = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject: "Password reset OTP",
        text: `Your OTP for resetting your password is ${otp}`,
      };

      await transporter.sendMail(mailOption);

      return res.json({
        success: true,
        message: "Reset OTP sent successfully",
      });
    } catch (error) {
      return res.json({ success: false, message: error.message });
    }
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//Reset user password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.json({ success: false, message: "All fields are required" });
  }

  try {
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP" });
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP expired" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpireAt = 0;

    await user.save();

    return res.json({
      success: true,
      message: "Password has been reset successfully",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};
