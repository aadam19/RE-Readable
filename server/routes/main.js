const express = require('express');
const router = express.Router();
const Post = require('../models/Post')
const User = require('../models/User')
const UserOTPVerification = require('../models/UserOTPVerification')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");

const jwtSecret = process.env.JWT_SECRET;

// HELPER FUNCTIONS
function truncateString(str, num) {
    if (str.length <= num) {
        return str;
    }
    return str.slice(0, num) + '...';
}

function censorEmail(email) {
    const [localPart, domain] = email.split('@');
    const censoredLocalPart = localPart.slice(0, 2) + '*****';
    const censoredDomain = domain.split('.').map((part, index) => index === 0 ? '**' : part).join('.');
    return `${censoredLocalPart}@${censoredDomain}`;
}

/* GET HOME */
router.get('', async (req, res) => {  
    try {
        const locals = {
            title: "RE | Readable",
            description: "eCommerce for used books"
        }

        let perPage = 24;
        let page = req.query.page || 1;

        const data = await Post.aggregate([
            { $sort: { createdAt: -1 } }
        ])
        .skip(perPage * (page - 1))
        .limit(perPage)
        .exec();

        const count = await Post.countDocuments();
        const nextPage = parseInt(page) + 1;
        const previousPage = parseInt(page) - 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);
        const hasPreviousPage = previousPage > 0;
        const lastPage = Math.ceil(count / perPage);

        res.render('index', { 
            locals, 
            data, 
            truncateString,
            count,
            perPage,
            current: page,
            nextPage: hasNextPage ? nextPage : null,
            previousPage: hasPreviousPage? previousPage : null,
            lastPage
        })
    } catch (error) {
        console.log(error)
    }
    
});


/* GET _ID */
router.get('/books/:id', async (req, res)=> {
    try {
        const locals = {
            title: "RE | Readable",
            description: "eCommerce for used books"
        }
        let slug = req.params.id;
        const data = await Post.findById({ _id: slug });

        res.render('books', {
            locals, 
            data
        });

    } catch (error) {
        console.log(error)
    }
})


/* POST SEARCH */
router.post('/search', async (req, res)=>{
    try {
        const locals = {
            title: "Search",
            description: "eCommerce for used books"
        }
        let searchTerm = req.body.searchTerm;
        const searchNoSpecial = searchTerm.replace(/[^a-zA-Z0-9]/g, "");

        const data = await Post.find({ 
            $or: [
                { title: { $regex: new RegExp(searchNoSpecial, 'i') } },
                { body: { $regex: new RegExp(searchNoSpecial, 'i') } },
            ]
         });

        res.render("search", {
            data,
            locals,
            searchTerm,
            truncateString
        });
    } catch (error) {
        console.log(error)
    }
})


/* ACCOUNT */
router.get('/account', (req, res) => {
    return res.render('register', { messages: req.flash(), showRegisterForm: true });
});

router.post('/account', async (req, res) => {
    const { action } = req.body;

    if (action === 'login') {
        try {
            const { email, password } = req.body;
            
            if (!email || !password) {
                req.flash('error', 'All fields are required');
                return res.render('register', { messages: req.flash(), showRegisterForm: false });
            }

            const user = await User.findOne({ email });
            if (!user) {
                req.flash('error', 'Invalid email or password');
                return res.render('register', { messages: req.flash(), showRegisterForm: false });
            }

            isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                req.flash('error', 'Invalid email or password');
                return res.render('register', { messages: req.flash(), showRegisterForm: false });
            }
            
            const token = jwt.sign({ userId:user._id }, jwtSecret);
            res.cookie('token', token, { httpOnly: true });

            res.redirect('/dashboard');

        } catch (error) {
            req.flash('error', 'An error occurred');
            return res.redirect('/account');
        }

    }
    else if (action === 'register') {
        try {
            const { username, email, password, confirmPassword } = req.body;

            if (!username || !email || !password || !confirmPassword) {
                req.flash('error', 'All fields are required');
                return res.render('register', { messages: req.flash(), showRegisterForm: true });
            }

            emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
            if (!emailPattern.test(email)) {
                req.flash('error', 'Invalid email address');
                return res.render('register', { messages: req.flash(), showRegisterForm: true });
            }

            if (password !== confirmPassword) {
                req.flash('error', 'Passwords do not match');
                return res.render('register', { messages: req.flash(), showRegisterForm: true });
            }

            passwordAllowed = /^[a-zA-Z0-9!.@#$%^&*]{6,20}$/;
            if (!passwordAllowed.test(password)) {
                req.flash('error', 'Password must be 6-20 chars and contain at least one special character');
                return res.render('register', { messages: req.flash(), showRegisterForm: true });
            }

            const emailExists = await User.findOne({email});
            if (emailExists) {
                req.flash('error', 'Email already registered');
                return res.render('register', { messages: req.flash(), showRegisterForm: true });
            }
            const usernameExists = await User.findOne({username});
            if (usernameExists) {
                req.flash('error', 'Username already exists');
                return res.render('register', { messages: req.flash(), showRegisterForm: true });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            try {
                const user = await User.create({ 
                    email, 
                    username, 
                    password: hashedPassword,
                    verified: false
                });

                sendOTPVerificationEmail(req, { _id: user._id, email: user.email }, res);

                req.session.userId = user._id; 
                req.session.email = email;
                req.flash('success', 'Please verify your email address');
                return res.redirect('/otpvalidation');
            } catch (error) {
                res.status(500).json({ message: 'An error occurred', error });
            }
        } catch (error) {
            req.flash('error', 'An error occurred');
            return res.redirect('/account');
        }
    }
});

const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        req.flash('error', 'Unauthorized');
        return res.redirect('/account');
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        req.flash('error', 'Unauthorized');
        return res.redirect('/account');
    }
};

router.get('/dashboard', authMiddleware, async (req, res) => {
    res.render('user/dashboard', { messages: req.flash() });
    // try {
    //     const locals = {
    //         title: "Dashboard",
    //         description: "eCommerce for used books"
    //     }
    //     const user


});

/* OTP */
let transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

const sendOTPVerificationEmail = async (req, { _id, email }, res) => {    
    try {
        const otp = `${Math.floor(100000 + Math.random() * 900000)}`;
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'reReadable | OTP Verification',
            html: `<p>Enter this OTP to verify your account: <b>${otp}</b>.</p> 
                    <p>This OTP will expire in <b>5 minutes</b> </p>`
        };

        // Hash the OTP
        const saltRounds = 10;
        const hashedOTP = await bcrypt.hash(otp, saltRounds);
        const newOTPVerification = await new UserOTPVerification({
            userId: _id,
            otp: hashedOTP,
            createdAt: new Date(),
            expiresAt: new Date(new Date().getTime() + 5*60000)
        }).save();

        // Save the OTP to the database
        await newOTPVerification.save();
        transporter.sendMail(mailOptions);

    } catch (error) {
        console.log(error);
        req.flash('error', 'An error occurred');
        return res.render('register', { messages: req.flash(), showRegisterForm: true });
    }
};

router.get('/otpvalidation', (req, res) => {
    const userId = req.session.userId;
    const email = req.session.email;

    if (!userId || !email) {
        req.flash('error', 'Unauthorized access. Please register or log in.');
        return res.redirect('/account'); 
    }
    res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
});

router.post('/otpvalidation', async (req, res) => {
    try {
        const { userId } = req.body;
        const otp = req.body.otp.join('');  // Join OTP parts to form complete OTP

        if (!userId || !otp) {
            req.flash('error', 'OTP is required');
            return res.render('auth/otpvalidation', { messages: req.flash() });
        }

        const userOTPRecords = await UserOTPVerification.find({ userId });

        if (userOTPRecords.length <= 0) {
            req.flash('error', 'Account record does not exist or has already been verified');
            return res.render('register', { messages: req.flash() });
        }

        const { expiresAt, otp: hashedOTP } = userOTPRecords[0];

        if (expiresAt < new Date()) {
            await UserOTPVerification.deleteMany({ userId });
            req.flash('error', 'OTP has expired');
            return res.render('auth/otpvalidation', { messages: req.flash() });
        }

        const isOTPValid = await bcrypt.compare(otp, hashedOTP);
        if (!isOTPValid) {
            req.flash('error', 'Invalid OTP');
            return res.render('auth/otpvalidation', { messages: req.flash() });
        }

        // Mark user as verified
        await User.updateOne({ _id: userId }, { verified: true });
        await UserOTPVerification.deleteMany({ userId });

        req.flash('success', 'Account verified successfully. Please log in.');
        return res.render('register', { messages: req.flash(), showRegisterForm: false });
    } catch (error) {
        console.error(error);
        req.flash('error', 'An error occurred. Please try again.');
        return res.render('auth/otpvalidation', { messages: req.flash() });
    }
});


module.exports = router;