import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';

import transporter from '../config/nodeMailer.js';

export const register = async (req,res)=>{
    const {name,email,password}=req.body;
    if(!name || !email || !password)
    {
        return res.json({success:false,message:"Missing details"})
    }
    try {
        
        const existingUser = await userModel.findOne({email});
        if(existingUser)
        {
            return res.json({success:false,message:"User Already Exists"});
        }


        const hashedPassword = await bcrypt.hash(password,10);

        const user = new userModel({name,email,password:hashedPassword});

        await user.save();

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV==='production' ? 'none':'strict',
            maxAge:7*24*60*60*1000
        }
        );

        //sending welcome email
        const  mailOptions ={
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:'Welcome to Great Stack',
            text:`welcome your account has created with mail ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({success:true});
        
    } catch (error) {
        res.json({success:false,message:error.message})
    }
}

export const login = async (req,res)=>{
    const {email,password} = req.body;

    if(!email || !password)
    {
        res.json({success:false,message:"Email and password are required"});
    }

    try {
        const user = await userModel.findOne({email});
        if(!user)
        {
            return res.json({success:false,message:"Invalid message "})
        }
        const isMatch = await bcrypt.compare(password,user.password)
        if(!isMatch)
        {
            return res.json({success:false,message:"Invalid password"});
        }

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV==='production' ? 'none':'strict',
            maxAge:7*24*60*60*1000
        }
        )
        return res.json({success:true});

    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const logout = async (req,res)=>{
    try 
    {
        res.clearCookie('token',{ httpOnly:true,
            secure:process.env.NODE_ENV === 'production',
            sameSite:process.env.NODE_ENV==='production' ? 'none':'strict'})

        return res.json({success:true,message:"Logged Out"})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const sendVerifyOtp = async (req,res)=>{
    try
    {
        const {userId} = req.body;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified)
        {
            return res.json({success:false,message:"Account already verified"});
        }

        const otp = String(Math.floor(100000 + Math.random()*90000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24*60*60*1000;

        await user.save();

        const  mailOptions ={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Welcome to Great Stack',
            text:`verify your ${user.email} with otp ${otp}`
        }
        await transporter.sendMail(mailOptions);

        return res.json({
            success:true,
            message:'sucessfully verified'
        });

    }
    catch(error)
    {
        return res.json({success:false,message:error.message});
    }
}


export const verifyEmail = async (req,res)=>{
    const {userId,otp} = req.body;
    if(!userId||!otp)
    {
        return res.json({success:false,message:"missing detials"});
    }
    try {
        const user = await userModel.findById(userId);
        if(!user)
        {
            return res.json({success:false,message:"user not found"});
        }

        if(user.verifyOtp === ''||user.verifyOtp !== otp)
        {
            return res.json({
                success:false,message:"Invalid OTP"
            });
        }
        if(user.verifyOtpExpireAt < Date.now())
        {
            return res.json({
                success:false,message:"outdates OTP"
            });
        }
        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=0;
        await user.save();
        return res.json({success:true,message:"Email Verified sucessfully "});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const isAuthenticated = async (req,res)=>{

    try {
        
        return res.json({success:true});

    } catch (error) {
        return res.json({success:false,message:error.message});
    }

}

export const sendResetOtp = async (req,res)=>{
    const {email} = req.body;

    if(!email)
    {
        return res.json({success:false,message:"Email is Required"});
    }

    try 
    {
        const user = await userModel.findOne({email});
        if(!user)
        {
            return res.json({success:false,message:"User not found"});
        }

        const otp = String(Math.floor(100000 + Math.random()*90000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15*60*1000;

        await user.save();

        const  mailOptions ={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Reset otp',
            text:`reset your ${user.email} with otp ${otp}`
        }
        await transporter.sendMail(mailOptions);
        
        return res.json({
            success:true,
            message:"otp sent to your email"
        });
    }
    catch (error) 
    {
        return res.json({success:false,message:error.message});
    }
}

export const resetPassword = async (req,res)=>{
    const {email,otp,newPassword} = req.body
    if(!email || !otp || !newPassword)
    {
        return res.json({
            success:false,
            message:"email,otp,and new password are requried"    
        });   
    }
    try 
    {
        const user = await userModel.findOne({email});
        if(!user)
        {
            return res.json({
                success:false,
                message:"User not found"
            });
        }
        if(user.resetOtp === "" || user.resetOtp !== otp)
        {
            return res.json({
                success:false,
                message:"invalid otp"
            });
        }
        if(user.resetOtpExpireAt < Date.now())
        {
            return res.json({
                success:false,
                message:"otp Expired"
            });
        }
        const hashedPassword = await bcrypt.hash(newPassword,10);

        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpireAt = 0;
        await user.save();
        
        return res.json({
            success:true,
            message:"Password has been reset sucessfully "
        });
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}