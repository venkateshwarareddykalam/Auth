import userModel from "../models/userModel.js";

export const getUserData = async (req,res)=>{
    try 
    {
        const {userId} = req.body;
        
        const user = await userModel.findById(userId);

        if(!user)
        {
            return res.json({
                sucess:false,
                message:"User Not found"
            });
        }

       return res.json({
            sucess:true,
            userData:{
                name:user.name,
                isAccountVerified:user.isAccountVerified
            }
        });
    }
    catch (error) {
        return res.json({sucess:false,message:error.message});
    }
}