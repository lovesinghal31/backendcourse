import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import fs from "fs"

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
    return res.status(201).json(new ApiResponse(200,createdUser,"User registerd successfully"))
})

export { registerUser }