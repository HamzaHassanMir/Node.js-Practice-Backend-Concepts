import express from 'express'
import {User} from '../models/user.model.js'
import {asyncHandler} from "../utils/asyncHandler"
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        // throw an error instead, let the caller handle it
        throw new Error("Token Generation failed")
    }
}

const registerUser = asyncHandler(async (req,res) =>{
    // step1: get user details from frontend
    // step2: validations - not empty
    // step3: check if user already exists: username or email
    // step4: check for images , check for avatar
    // step5: upload them to cloudinary
    // step6: create user object
    // step7: remove password and refresh token fields from response
    // step8: check for user creation and return user else send error

    const {fullName, email, username, password} = req.body
    console.log(email);

    if([fullName, email, username, password].some((field) => field?.trim() === "")){
        return res.status(400).json({message: "All fields are required"})
    }

    const existedUser = User.findOne({
        $or: [{ username }, { email }]
    })

    if(existedUser){
        return res.status(409).json({message: "User with email or Username already exists"})
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if(!avatarLocalPath){
        return res.status(400).json({message: "Avatar is required"})
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        return res.status(400).json({message: "Avatar file is required"})
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email, 
        password,
        username: username.toLowerCase()
    })

     const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        return res.status(500).json({message: "Something went wrong while registering the user"})
    }

    return res.status(201).json({
        success: true,
        data: createdUser,
        message: "User registered successfully"
    })

})

const loginUser = asyncHandler(async(req,res)=>{
    // req body -> get data
    // check username or email
    // find user in database
    // check password
    // access and refresh token generate
    // send tokens in cookies
    
    const {email, username, password} = req.body

    if(!username || !email){
        return res.status(400).json({message: "username or password is required"})
    }

    const user = await User.findOne({
        $or: [{username} , {email}]
    })

    if(!user){
        return res.status(404).json({message: "User does not exist"})
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid){
        return res.status(401).json({message: "Password Incorrect"})
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .status(200)
    .json({
        data: {
            user: loggedInUser, accessToken, refreshToken
        },
        message: "User logged In Successfully"
    })
})

const logoutUser = asyncHandler(async (req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken", options)
    .json({message: "user loggout successfully"})

})

const refreshAccessToken = asyncHandler(async(req,res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        return res.status(401).json({message: "unauthorized request"})
    }

    try {
        const decodedToken = jwt.verify(
        incomingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET)
        
        const user = await User.findById(decodedToken?._id)
        
        if(!user){
        return res.status(401).json({message: "Invalid refresh token"})

        if(incomingRefreshToken !== user?.refreshToken){
            return res.status(401).json({message: "Refresh Token is expired or used"})
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)

        return res
        .status(200)
        .cookie("accessToken", accessToken)
        .cookie("refreshToken", newRefreshToken)
        .json({
            success: true,
            message: "Access Token Refreshed",
            data: {
            accessToken,      
            refreshToken: newRefreshToken}
        })
    }
    
    } catch (error) {
        return res.status(401).json({message: error?.message || "Invalid refresh Token"})
    }
})

const changeCurrentPassword = asyncHandler(async(req,res)=>{
    const {oldPassword , newPassword} = req.body
    
    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        res.status(400).json({message: "Invalid old password"})
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json({message: "Password changed successfully"})

})

const getCurrentUser = asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json({
        success: true,
        data: req.user,
        message: "Current User Fetched Successfully"
    })
})

const updateAccountDetails = asyncHandler(async(req,res)=>{
    const {fullname, email} = req.body

    if(!fullname || !email){
        return res.status(400).json({message: "all fields are required"})
    }
 
    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullname,
                email
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json({
        success: true,
        data: user,
        message: "Account Details Updated Successfully"
    })
})



export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails

}

