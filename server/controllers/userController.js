import UserModel from "../models/userModel.js";

export const getUserData = async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({ 
            success:true,
            userData: {
                name: user.name,
                isAccountVerified: user.isAccountVerified
            }
        })
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}