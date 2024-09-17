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

// Helper function for readability
const renderWithMessages = (res, view, messages, showRegisterForm, email = '', username = '') => {
    res.render(view, {
        messages: messages,
        showRegisterForm: showRegisterForm,
        email: email || '',
        username: username || ''
    });
};

const isValidEmail = (email) => {
    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    return emailPattern.test(email);
};

const isValidPassword = (password) => {
    const passwordAllowed = /^[a-zA-Z0-9!.@#$%^&*]{6,20}$/;
    return passwordAllowed.test(password);
};

router.get('/account', (req, res) => {
    if (req.cookies.token) {
        return res.redirect('/dashboard');
    }
    return renderWithMessages(res, 'register', req.flash(), true);
});

router.post('/account', async (req, res) => {
    const { action } = req.body;

    // Common validation logic
    console.log(req.body);
    console.log(action);
    const { email, password, username, confirmPassword } = req.body;
    if (!email || !password || (action === 'register' && (!username || !confirmPassword))) {
        req.flash('error', 'All fields are required');
        return renderWithMessages(res, 'register', req.flash(), action === 'register', email, username);
    }

    if (!isValidEmail(email)) {
        req.flash('error', 'Invalid email address');
        return renderWithMessages(res, 'register', req.flash(), action === 'register', email, username);
    }

    try {
        if (action === 'login') {
            const user = await User.findOne({ email });
            const isPasswordValid = user && await bcrypt.compare(password, user.password);
            
            if (!isPasswordValid) {
                req.flash('error', 'Invalid email or password');
                return renderWithMessages(res, 'register', req.flash(), false, email);
            }

            if (!user.verified) {
                await verifyUser(req, { _id: user._id, email: user.email }, res);
                req.flash('success', 'Please verify your email address');
                return res.redirect('/otpvalidation');
            }

            const token = jwt.sign({ userId: user._id }, jwtSecret);
            res.cookie('token', token, { httpOnly: true });
            return res.redirect('/dashboard');
        } 
        else if (action === 'register') {
            if (password !== confirmPassword) {
                req.flash('error', 'Passwords do not match');
                return renderWithMessages(res, 'register', req.flash(), true, email, username);
            }

            if (!isValidPassword(password)) {
                req.flash('error', 'Password must be 6-20 chars and contain at least one special character');
                return renderWithMessages(res, 'register', req.flash(), true, email, username);
            }

            const emailExists = await User.findOne({ email });
            const usernameExists = await User.findOne({ username });

            if (emailExists) {
                req.flash('error', 'Email already registered');
                return renderWithMessages(res, 'register', req.flash(), true, '', username);
            }

            if (usernameExists) {
                req.flash('error', 'Username already exists');
                return renderWithMessages(res, 'register', req.flash(), true, email, '');
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const user = await User.create({
                email,
                username: username.trim(),
                password: hashedPassword,
                verified: false
            });

            await verifyUser(req, user, res);
            req.flash('success', 'Please verify your email address');
            return res.redirect('/otpvalidation');
        }
    } catch (error) {
        req.flash('error', 'An error occurred');
        return res.redirect('/account');
    }
});

const verifyUser = async (req, user, res) => {
    try {
        await sendOTPVerificationEmail(req, { _id: user._id, email: user.email }, res);
        req.session.userId = user._id; 
        req.session.email = user.email;
    } catch (error) {
        console.error(error);
        req.flash('error', 'An error occurred while verifying user');
        return res.redirect('/account');
    }
};

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
        return renderWithMessages(res, 'register', req.flash(), true);
    }
};

router.get('/otpvalidation', (req, res) => {
    console.log(req.session);
    const userId = req.session.userId;
    const email = req.session.email;

    if (!userId || !email) {
        req.flash('error', 'Unauthorized access. Please register or log in.');
        return res.redirect('/account'); 
    }
    res.render('auth/otpvalidation', { messages: req.flash(), email:censorEmail(email), userId });
});

router.post('/otpvalidation', async (req, res) => {
    try {
        const { userId } = req.body;
        const otp = req.body.otp.join('');
        email = req.session.email

        if (!userId || !otp) {
            req.flash('error', 'OTP is required');
            return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
        }

        const userOTPRecords = await UserOTPVerification.find({ userId });

        if (userOTPRecords.length <= 0) {
            req.flash('error', 'Account record does not exist or has already been verified');
            return renderWithMessages(res, 'register', req.flash(), false);
        }

        const { expiresAt, otp: hashedOTP } = userOTPRecords[0];

        if (expiresAt < new Date()) {
            await UserOTPVerification.deleteMany({ userId });
            req.flash('error', 'OTP has expired');
            return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
        }

        const isOTPValid = await bcrypt.compare(otp, hashedOTP);
        if (!isOTPValid) {
            req.flash('error', 'Invalid OTP');
            return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
        }

        // Mark user as verified
        await User.updateOne({ _id: userId }, { verified: true });
        await UserOTPVerification.deleteMany({ userId });

        req.flash('success', 'Account verified successfully. Please log in.');
        return renderWithMessages(res, 'register', req.flash(), false);
    } catch (error) {
        console.error(error);
        req.flash('error', 'An error occurred. Please try again.');
        return res.render('auth/otpvalidation', { messages: req.flash(), email: req.session.email, userId: req.session.userId });                                                                                                                                       
    }
});

/* PROFILE DASHBOARD */
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


module.exports = router;