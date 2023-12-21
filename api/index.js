
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const User = require('./models/User');
const Post = require('./models/Post');
const bcrypt = require('bcrypt');
const app = express();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');

const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);
const secret="asdasjfhsdfhowiehh98wy9khdfwkf";

app.use(cors({credentials:true,origin:'http://localhost:3000'}));
app.use(express.json());
app.use(cookieParser()); 
app.use('/uploads', express.static(__dirname + '/uploads'));

mongoose.connect('mongodb+srv://prasadsaoji000:%21%40%23%24%25%5E%26%2A%28%29@cluster0.dktkwah.mongodb.net/?retryWrites=true&w=majority');

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userDoc = await User.create({
            username,
            password: bcrypt.hashSync(password, salt),
        });
        res.json(userDoc);
    } catch (e) {
        console.error('Registration error:', e);
        res.status(400).json({ error: 'Registration failed' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userDoc = await User.findOne({ username });

        if (!userDoc) {
            // User not found
            res.status(400).json('User not found');
            return;
        }

        const passOk = bcrypt.compareSync(password, userDoc.password);

        if (passOk) {
            jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
                if (err) {
                    console.error('JWT Sign Error:', err);
                    throw err;
                }
                console.log('Generated Token:', token);
                res.cookie('token', token).json({
                    id:userDoc._id,
                    username,
                });
            });
        } else {
            // Incorrect password
            res.status(400).json('Wrong Credentials');
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/profile',(req,res)=>{
    const {token}=req.cookies;
    jwt.verify(token, secret, {}, (err,info)=>{
        if(err) throw err;
        res.json(info);
    }); 
});

app.post('/logout',(req,res)=>{
    res.cookie('token','').json('ok');
})

app.post('/post',uploadMiddleware.single('file') ,async (req,res)=>{
    const {originalname,path}=req.file;
    const parts=originalname.split('.');
    const ext= parts[parts.length - 1];
    const newPath=path+'.'+ext;
    fs.renameSync(path,newPath);

    const {token}=req.cookies;
    jwt.verify(token, secret, {}, async(err,info)=>{
        if(err) throw err;
        const{title,summary,content}=req.body;
        const postDoc=await Post.create({
            title,
            summary,
            content,
            cover:newPath,
            author:info.id,
        });
        res.json(postDoc); 
    });
});

    app.put('/post', uploadMiddleware.single('file'), async (req, res) => {
        let newPath = null;
        if (req.file) {
            const { originalname, path } = req.file;
            const parts = originalname.split('.');
            const ext = parts[parts.length - 1];
            newPath = path + '.' + ext;
            fs.renameSync(path, newPath);
        }
    
        const { token } = req.cookies;
        jwt.verify(token, secret, {}, async (err, info) => {
            if (err) throw err;
            const { id, title, summary, content } = req.body;
            const postDoc = await Post.findById(id);
    
            if (!postDoc) {
                return res.status(404).json('Post not found');
            }
    
            const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(info.id);
            if (!isAuthor) {
                return res.status(400).json('You are not the author');
            }
    
            const updatedPost = await Post.findByIdAndUpdate(id, {
                title,
                summary,
                content,
                cover: newPath ? newPath : postDoc.cover,
            }, { new: true });
    
            res.json(updatedPost);
        });
    });
    
    app.get('/post', async (req,res)=>{
        res.json(
        await Post.find()
         .populate('author', ['username'])
         .sort({createdAt: -1})
         .limit(20)
         );
    });

    app.get('/post/:id', async(req,res)=>{
        const{id}=req.params;
        //  res.json(req.parmas);
        const postDoc=await Post.findById(id).populate('author',['username']);
        res.json(postDoc);
    });


app.listen(4000);