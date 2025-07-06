import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import fs from "fs"
import jwt from 'jsonwebtoken'


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
    // get user details from frontend
    // validation - not empty
    // check if user already exist: username,email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove passoword and refresh token field from response
    // check for user creation
    // return response
    const {fullName, email, username, password} = req.body
    // console.log(`fullName: ${fullName}\nemail: ${email}\nusername: ${username}\npassword: ${password}`);
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
    // const avatarLocalPath = req.files?.avatar[0]?.path;
    let avatarLocalPath;
    if(req.files && Array.isArray(req.files.avatar) && req.files.avatar.length > 0){
        avatarLocalPath = req.files.avatar[0].path;
    }
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }
    // console.log("req.files : ",req.files); // req. files
    if(!avatarLocalPath){
        fs.unlinkSync(coverImageLocalPath)
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
        username: username,
    })
    const createdUser = await User.findById(user._id).select("-password -refreshToken")
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering the user")
    }
    console.log("user registered!!!")
    return res.status(201).json(new ApiResponse(200,createdUser,"User registerd successfully"))
})

const loginUser = asyncHandler(async (req,res) => {
    // req.body -> data
    // username or email (empty or not)
    // username or email based search in db for user
    // check if password matches or not
    // gen access and refresh token
    // send cookies
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

    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {httpOnly: true,secure: true}

    console.log("user logged in")
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {user: loggedInUser,accessToken,refreshToken},
            "user logged in successfully"
        )
    )
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
    
        const {accessToken,newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
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

export { registerUser, loginUser, logoutUser, refreshAccessToken }