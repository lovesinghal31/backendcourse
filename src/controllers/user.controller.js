import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import fs from "fs"
import jwt from 'jsonwebtoken'
import mongoose from "mongoose"
import {otpStore} from "../utils/otpStore.js"
import sendEmail from "../utils/sendEmail.js"


const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500,"something went wrong while generating access and refresh tokens")
    }
}


const registerUser = asyncHandler(async (req,res) => {
    const {fullName, email, username, password} = req.body
    if([fullName,email,username,password].some((field)=> field?.trim() === "")){
        throw new ApiError(400,"All field is required")
    }


    const exitedUser = await User.findOne({$or: [{username}, {email}]})
    if(exitedUser){
        // cleaning the temp folder when this error shows
        // --------START HERE---------
        let avatarLocalPath;
        if(req.files && Array.isArray(req.files.avatar) && req.files.avatar.length > 0){
            avatarLocalPath = req.files.avatar[0].path;
        }
        let coverImageLocalPath;
        if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
            coverImageLocalPath = req.files.coverImage[0].path;
        }
        if(avatarLocalPath){
            fs.unlinkSync(avatarLocalPath)
        }
        if(coverImageLocalPath){
            fs.unlinkSync(coverImageLocalPath)
        }
        // ---------END HERE-----------
        throw new ApiError(409,"User with email or username already exist")
    }


    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    otpStore.set(email, {
        otp, 
        userData: {
            fullName, 
            email, 
            username, 
            password,
            files: req.files
        }, 
        expiresAt
    });

    await sendEmail({
        to: email,
        subject: "Chai - OTP for registration",
        html: `<table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 20px 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
                <tr>
                    <td align="center">
                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 40px;">
                        <tr>
                        <td align="center" style="padding-bottom: 30px;">
                            <h2 style="color: #333333; margin: 0;">OTP Verification</h2>
                        </td>
                        </tr>
                        <tr>
                        <td style="font-size: 16px; color: #555555; line-height: 1.6;">
                            <p>Dear ${fullName},</p>
                            <p>Your OTP for completing the registration process is:</p>
                            <p style="font-size: 24px; font-weight: bold; color: #0d6efd; margin: 20px 0;">${otp}</p>
                            <p>This OTP is valid for <strong>10 minutes</strong>. Please do not share it with anyone.</p>
                            <p>If you did not request this, please ignore this email.</p>
                        </td>
                        </tr>
                        <tr>
                        <td style="padding-top: 30px; font-size: 14px; color: #999999;">
                            <p>Thank you,<br>The Tripverse Team</p>
                        </td>
                        </tr>
                    </table>
                    </td>
                </tr>
               </table>`
    });

    console.log("OTP sent to email:", email);
    
    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {}, 
            "OTP sent to your email. Please verify to complete registration."
        )
    )
})

const verifyRegistrationOtp = asyncHandler(async (req, res) => {
    const {email, submittedOtp} = req.body;
    if(!email || !submittedOtp) {
        throw new ApiError(400, "Email and OTP are required");
    }

    const record = otpStore.get(email);
    if(!record) {
        throw new ApiError(404, "No OTP found for this email");
    }

    if(Date.now() > record.expiresAt) {
        otpStore.delete(email);
        throw new ApiError(410, "OTP has expired");
    }

    if(record.otp !== submittedOtp) {
        throw new ApiError(400, "Invalid OTP");
    }

    const {fullName, username, password, files} = record.userData;

    let avatarLocalPath;
    if(files && Array.isArray(files.avatar) && files.avatar.length > 0){
        avatarLocalPath = files.avatar[0].path;
    }
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(files && Array.isArray(files.coverImage) && files.coverImage.length > 0){
        coverImageLocalPath = files.coverImage[0].path;
    }
    // console.log("req.files : ",req.files); // req. files
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400,"Avatar file upload failed");
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username,
    })
    const createdUser = await User.findById(user._id).select("-password -refreshToken")
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }

    otpStore.delete(email); // Clear OTP after successful registration
    console.log("user registered!!!")

    return res
    .status(201)
    .json(
        new ApiResponse(
            201,
            createdUser,
            "User registered successfully. Please login to continue."
        )
    )
});

const loginUser = asyncHandler(async (req,res) => {
    const {email,username,password} = req.body
    if(!(email || username)){
        throw new ApiError(400,"username or password required")
    }

    const user = await User.findOne({$or: [{email},{username}]})
    if(!user){
        throw new ApiError(404,"User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        throw new ApiError(401,"Invalid user credentials")
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    otpStore.set(user.email, {otp, userId: user._id, expiresAt});
    
    await sendEmail({
        to: user.email,
        subject: "Chai - OTP for login",
        html: `<table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 20px 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
                <tr>
                    <td align="center">
                    <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05); padding: 40px;">
                        <tr>
                        <td align="center" style="padding-bottom: 30px;">
                            <h2 style="color: #333333; margin: 0;">Login OTP</h2>
                        </td>
                        </tr>
                        <tr>
                        <td style="font-size: 16px; color: #555555; line-height: 1.6;">
                            <p>Dear ${user.fullName},</p><br>
                            <p>Your OTP for logging into your account is:</p><br>
                            <p style="font-size: 24px; font-weight: bold; color: #0d6efd; margin: 20px 0;">${otp}</p><br>
                            <p>This OTP is valid for <strong>10 minutes</strong>. Please do not share it with anyone.</p><br>
                            <p>If you did not request this, please secure your account immediately.</p>
                        </td>
                        </tr>
                        <tr>
                        <td style="padding-top: 30px; font-size: 14px; color: #999999;">
                            <p>Thank you,<br>The TripVerse Team</p>
                        </td>
                        </tr>
                    </table>
                    </td>
                </tr>
               </table>`
    });

    console.log("OTP sent to email:", user.email);

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            {},
            "OTP sent to your email. Please verify to login.",
        )
    )
})

const verifyLoginOtp = asyncHandler(async (req, res) => {
    const {email, submittedOtp} = req.body;
    if(!email || !submittedOtp) {
        throw new ApiError(400, "Email and OTP are required");
    }

    const record = otpStore.get(email);
    if(!record) {
        throw new ApiError(404, "No OTP found for this email");
    }

    if(Date.now() > record.expiresAt) {
        otpStore.delete(email);
        throw new ApiError(410, "OTP has expired");
    }

    if(record.otp !== submittedOtp) {
        throw new ApiError(400, "Invalid OTP");
    }

    console.log("token generated for user: ", record.userId);
    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(record.userId);

    const loggedInUser = await User.findById(record.userId).select("-password -refreshToken");

    const options = {httpOnly: true, secure: true};

    otpStore.delete(email); // Clear OTP after successful login
    console.log("user logged in");

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {user: loggedInUser, accessToken, refreshToken},
            "User logged in successfully"
        )
    );
})

const logoutUser = asyncHandler(async (req,res) => {
    await User.findByIdAndUpdate(req.user._id,
        // {$set: {
        //     refreshToken: undefined
        // }},
        {$unset: {
            refreshToken: 1
        }},
        {new: true}
    )

    const options = {httpOnly: true,secure: true}

    console.log("user logged out")
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"user logged out"))
})

const refreshAccessToken = asyncHandler(async (req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if(!incomingRefreshToken) {
        throw new ApiError(401,"unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken._id)
        if(!user){
            throw new ApiError(401,"invalid refresh token")
        }
        
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401,"refresh token expired or used")
        }
    
        const options = {httpOnly: true,secure: true}
    
        const {accessToken,refreshToken: newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        console.log("token refreshed");
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(new ApiResponse(
            200,
            {accessToken,refreshToken: newRefreshToken},
            "Access token refreshed"
        ))
    } catch (error) {
        throw new ApiError(401,error?.message || "Invaild refresh token")
    }
})

const changeCurrentPassword = asyncHandler(async (req,res) => {
    const {oldPassword, newPassword} = req.body

    const workingUser = await User.findById(req.user?._id)

    const isPasswordValid = await workingUser.isPasswordCorrect(oldPassword)
    if(!isPasswordValid){
        throw new ApiError(400,"Invalid old Password")
    }

    workingUser.password = newPassword
    await workingUser.save({validateBeforeSave: false})

    console.log("password changed")
    return res
    .status(200)
    .json(new ApiResponse(200,{},"Password changed successfully"))
})

const getCurrentUser = asyncHandler(async (req,res) => {
    console.log("current user fetched")
    return res
    .status(200)
    .json(new ApiResponse(200,req.user,"current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async (req,res) => {
    const {fullName,email} = req.body
    if(!fullName || !email){
        throw new ApiError(400, "all fields are required")
    }

    const updatedUser = await User.findByIdAndUpdate(req.user?._id,{
        $set: {fullName,email}
    },{new: true}).select("-password")

    console.log("account details updated")
    return res
    .status(200)
    .json(new ApiResponse(200,updatedUser,"Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async (req,res) => {
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath) {
        throw new ApiError(400,"avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    if(!avatar.url){
        throw new ApiError(400,"error while uploading avatar on cloudinary")
    }

    const updatedUser = await User.findByIdAndUpdate(req.user?._id,{
        $set: {avatar: avatar.url}
    },{new: true}).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,updatedUser,"avatar image updated successfully"))
})

const updateUserCoverImage = asyncHandler(async (req,res) => {
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath) {
        throw new ApiError(400,"cover image is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!coverImage.url){
        throw new ApiError(400,"error while uploading cover image on cloudinary")
    }

    const updatedUser = await User.findByIdAndUpdate(req.user?._id,{
        $set: {coverImage: coverImage.url}
    },{new: true}).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,updatedUser,"cover image updated successfully"))
})

const getUserChannelProfile = asyncHandler(async (req,res) => {
    const {username} = req.params;
    if(!username?.trim()){
        throw new ApiError(400,"username is missing!");
    }

    const channel =  await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id,"$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,
                createdAt: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
            }
        }
    ])
    if(!channel.length){
        throw new ApiError(404,"channel does not exists!");
    }

    console.log("channel: ",channel) // to see what does channel return

    return res
    .status(200)
    .json(new ApiResponse(200,channel[0],"User channel fetched successfully"))

})

const getWatchHistory = asyncHandler(async (req,res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1,
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner",
                            }
                        }
                    }
                ]
            }
        }
    ])

    // to console whole user and user[0]

    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            user[0].watchHistory,
            "User watch history fetched successfully!"
        )
    )
})

export {
    registerUser,
    verifyRegistrationOtp,
    loginUser,
    verifyLoginOtp,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}