// Server.js
import app from "./app.js";
import dotenv from "dotenv";
dotenv.config();
const POST= process.env.PORT||4000;
app.listen(PORT,()=>console.log("API running on http://localhost:${PORT}"));

//App.js
import express from "express";
import cors from "cors";
import morgan from "morgan";
import helmet from "helment";
import compression from "compression";
import "./config/db.js";
import authRoutes from "./routes/authRoutes.js";
import postRoutes from "./routes/postRoutes.js";
import commentRoutes from "./routes/commentRoutes.js";
import errorHandler from "./middleware/errorHandler.js";

const app= express();

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({limit:"1mb"}));
app.use(morgan("dev"));

app.get("/", (_req, res)=>res.json({status: "ok",name: "Blog API"}));

app.use("/api/auth", authRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);
app.use(errorHandler);

// Config/db.js
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

mongoose.set("strictQuery", true);

mongoose.connect(process.env.MONGO_URL).then (()=>console.log("MongoDB connected"))
.catch((err)=>{console.error("Mongo connection error:", err.message)});

// MODELS
// models/User.js

import mongoose from "mongoose";
import bcrypt from "bcryptjs";

export const roles= ["admin", "author", "reader"];

const userSchema= new mongoose.Schema({
    name:{
        type: string, required: true, trim: true},
    email:{
        type: string, required: true, unique: true, index: true},
    password:{
        type: string, required: true
    },
    role:{
        type: string, enum: roles, default: "reader"
    },
    isActive:{
        type: Boolean, default: true
    },
}, {timestamps: true}
);

//models/Post.js

import mongoose from "mongoose";

const postSchema= new mongoose.Schema({
    tittle:{
        type: string, required: true, trim: true
    },
    slug:{
        type: string, required: true, unique: true, index: true
    },
    content:{
        type: string, required: true
    },
    tags:[{
        type: string, trim: true
    }],
    author:{
        type: mongoose.Schema.Types.ObjectId, ref: "User", required:true
    }, 
    isPublished:{
        type: Boolean, default: false
    }, 
    deletedAt:{
        type: Date, default: null
    },
}, {timestamps:true});

postSchema.index({tittle:"text", content:"text", tags:1});

//models/comment.js
import mongoose from "mongoose";
const commentSchema= new mongoose.Schema({
    post:{
        type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true
    },
    author:{
        type: mongoose.Schema.Types.ObjectId, ref: "User", required: true
    },
    content:{
        type: string, required: true, trim: true
    },
    deletedAt:{
        type: Date, default: null
    },
}, {timestamps: true});

//Middleware & Utils
// middleware/auth.js

import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import User from "../models/User.js";
dotenv.config();

export const auth=async(req,_res, next)=>{
    try{
        const header= req.headers.authorization||""
        const token= header.startsWith("Bearer")?
        header.split("")[1]: null;
        if(!token)throw Object.assign(new error("Authentication required"), {status: 401});
        const payload= jwt.verify(token, process.env.JWT_SECRET);
        const user= await User.findById(payload.id);
        if(!user||!user.isActive) throw Object.assign(new error("Invalid or inactive user"),{status:401});
        req.user={id: user._id.toString(), role: user.role};
        next();
    } catch(e){
        e.status= e.status||401; next (e);
    }
};

//middleware/requireRole.js
export const requireRole= (...allowed)=>(req, _res, next)=>{
    if(! req.user)
        return next(Object.assign(new error("Not authenticated"), {staus:401}));
    if(!allowed.includes(req.user.role))
        return next(Object.assign(new error("Forbidden"),{status:403}));
};

// Validators
//authValidators.js
import{body} from "express-validator";

export const registerVlidator= [
    body("name").trim().notEmpty(),
    body("email").isEmail(),
    body("password").isLength({min:6}),
    body("role").optional().isIn(["admin", "author", "render"]),
];
export const loginValidator=[
    body("email").isEmail(),
    body("password").isLength({min:6}),
];

// postValidators.js
import{body, param, query,} from "express-validator";

export const CreatePostValidator= [
    body("tittle"). trim().noEmpty(),
    body("slug"). trim().notEmpty(),
    body("content"). trim().notEmpty(),
    body("tags").optional().isArray(),

    body("isPublished").optional().isBoolean(),
];

export const updatePostValidator= [param("id").isMongoId(),
    body("tittle").optional().trim().notEmpty(),
    body("slug").optional().trim().notEmpty(),
    body("content").optional().trim().notEmpty(),
    body("tags").optional().isArray(),
    body("isPublished").optional().isBoolean(),
];

export const listPostValidator=[
    query("page").optional().isInt({min: 1}),
    query("limit").optional().isInt({min: 1, max: 100}),
    query("author").optional().isMongoId(),
    query("q").optional().isString(),
    query("published").optional().isBoolean(),
];

//commentValidators.js
import{body, param} from "express-validator";

export const createCommentValidator= [
    body("postId").isMongoId(),
    body("content").trim().notEmpty(),
];

export const updateCommentValidator= [
    param("id").isMongoId(),
    body("content").trim().notEmpty(),
];

//Controllers
//authController.js

import{validationResult} from "express-validator";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import User from "../models/User.js";
import asyncHandler from "../utils/asyncHandler.js";
dotenv.config();

const sign= (user)=> jwt.sign({id:user._id, role:user.role}, process.env.JWT_SECRET, {expiresIn:
    process.env.JWT_EXPIRES_IN||"id",
});

export const register= asyncHandler(async(req, res)=>{
    const errors= validationReuslt(req);
    if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()});
    const{name, email, password, role}= req.body;
    const exists= await User.findOne({email});
    if(exists) return res.status(409).json({error:"Email already in use"});
    const user= await User.create({name, email, password, role});
    const token= sign(user);
    res.status(201).json({user:{id:user._id, name: user.name, email: user.email, role: user.role}, token, });
});
export const login= asyncHandler(async(req, res)=>{
    const errors= validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()});
});
const {email, password}= req.body;
const user= await User.findOne({email});
if (!user) return res.status(401).json({error: "Invalid credentials"});

const ok= await user.comparePassword(password);
if (!ok) return res.status(401).json({error: "invalid credentaials"});
const token= sign(user);
res.json({user: {id: user_id, name: user.name, email: user.email, role: user.role}, token,});

// postController.js
import{validationResult} from "express-validator";
import Post from "../models/Post.js";
import asyncHandler from "../utils/asyncHandler.js";

const isowneroradmin= (req, post)=> req.user.role==="admin"||
post.author.toString()===req.user.id;

export const createPost= asyncHandler(async(req, res)=>{
    const errors= validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({errors: errors.array()});

    const{tittle, slug, content, tags=[], isPublished= false}= req.body;
    const exists= await post.findOne({slug});
    if (exists) return res.status (409).json({error: "slug already in use"});

    const post= await Post.create({tittle, slug, content, tags, isPublished, author: req.user.id});
    res.status(201).json({post});
});
export const listPosts= asyncHandler(async (req, res)=>{
    const{page=1, limit= 10, q, author, published}= req.query;
    const filter={deletedAt: null};
    if (q) filter.$text={$search:q};
    if(author) filter.author= author;
    if (typeof published !=="undefined")filter.isPublished= pusblished=="true";

    const skip= (Number(page)-1)*
    Number(limit);
    const[items, total]= await Promise.all([
        Post.find(filter).populate("author", "name email role")
        .sort({createdAt: -1})
        .skip(skip)
        .limit(Number(limit)),
        Post.countDocuments(filter),
    ]);
    res.json({
        items, 
        pagination: {page: Number(page),
            limit: Number(limit), total, pages: Math.ceil(total/ Number(limit))
        },
    });
});

export const getPost= asyncHandler(async(req, res)=>{
    const post= await Post.findOne({_id:req.params.id, deletedAt: null}).populate("author", "name email role");
    if(!post) return res.status(404).json({error: "Post not found"});
    res.json({post});
});

export const updatePost= asyncHandler(async(req, res)=>{
    const errors= validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()});
    const post= await Post.findById(req.params.id);
    if(!post||post.deletedAt) return res.status(404).json({error: "Post not found"});
    if (!isOwnerOrAdmin(req, post)) return res.status(403).json({error: "Forbidden"});

    const updatetable= ["tittle", "slug", "content", "tags", "isPusblished"];
    updatetable.forEach((k)=>(typeof req.body[k]!=="undefined"?(post[k]=req.body[k]): null)); await post.save();
res.json({post});
});

export const deletePost= asyncHandler(async(req, res)=>{
    const post= await Post.findById(req.params.id);
    if(!post||post.deletedAt) return res.status(404).json({error: "Post not found"});
    if (!isOwnerOrAdmin(req, post)) return res.status(403).json({error: "forbidden"});
    post.deletedAt= new Date();
    await post.save();
    res.status(204).send();
});

// commentController.js
import {validationResult} from "express-validator";
import comment from "../models/Comment.js";
import Post from "../models/Post.js";
import asyncHandler from "../utils/asyncHandler.js";

const isOwnerOrAdmin= (req, comment)=> req.user.role==="admin"||
comment.author.toString()===req.user.id;

export const createComment= asyncHandler(async(req, res)=>{
    const errors= validationResult(req);
    if(!errors.isEmpty())return res.status(400).json({errors: errors.array()});

    const {postId, content}= req.body;
    const post= await Post.findById(postId);
    if(!post||post.deletedAt)return res.status(404).json({error:" post not found"});

    const comments= await Comment.find(filter).populate("author", "name email role").sort({createdAt: -1});
    res.json({items: comments});
});
export const updateComment= asyncHandler(async(req, res)=>{
    const errors= validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({errors:errors.array()});
    const comment= await Comment.findById(req.params.id);
    if(!comment||comment.deletedAt) return res.status(404).json({error: "comment not found"});
    if (isOwnerOrAdmin(req, comment)) return res.status(403).json({error: "forbidden"});
    comment.content= req.body.content;
    await comment.save();
    res.json({comment});
});
export const deleteComment= asyncHandler(async(req, res)=>{
    const comment= await Comment.findById(req.params.id);
    if(!comment||comment.deletedAt) return res.status(404).json({error: "Comment not found"});
    if (!isOwnerOrAdmin(req, comment))return res.status(403).json({error: "forbidden"});
    comment.deletedAt= new Date();
    await comment.save();
    res.status(204).send();
});

//Routes
//authRoutes.js
import{Router} from "express";
import {register, login, me} from "../controllers/authController.js";
import {registerValidator, loginValidator} from "../validators/authValidators.js";
import {auth} from "../middleware/auth.js";


router.post("/register", registerValidator, register);
router.post("/login", loginValidator, login);
router.get("/me", auth, me);


//postRoutes.js
import{Router} from "express";
import{createPost, listPosts, getPost, updatePost, deletePost} from "../controllers/postController.js";
import{auth} from "../middleware/auth.js";
import{requireRole} from "../middleware/requireRole.js";
import{createPostValidator, updatePostValidator, listPostValidator} from "../validators/postValidators.js";


router.get("/", listPostValidator, listPosts);
router.get("/:id", getPots);
router.post("/", auth, requireRole("admin", "author"), createPostValidator, createPost);
router.patch("/:id", auth, requireRole("admin", "author"), updatePostValidator, updatePost);
router.delete("/:id", auth, requireRole("admin", "author"), deletePost);

// commentRoutes.js
import{Router} from "express";
import{createComment, listComments, updateComment, deleteComment} from "../controllers/commentControllers.js";
import{auth} from "../middleware/auth.js";
import{requireRole} from "../middleware/requireRole.js";
import{createCommentValidator, updateCommentValidator} from "../validators/commentValidators.js";

const router= Router();

router.get("/", listComments);
router.post("/", auth, requireRole("admin", "author", "reader"), createCommentValidator, createComment);
router.delete("/:id", auth, requireRole("admin", "author", "reader"), deleteComment);

export default router; 




