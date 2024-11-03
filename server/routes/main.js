const express = require('express');
const router = express.Router();
const Post = require('../models/Post')
const User = require('../models/User')
const UserOTPVerification = require('../models/UserOTPVerification')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const e = require('connect-flash');
const mongoose = require('mongoose');
const { ObjectId } = mongoose.Types;

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
router.get('/books/:id', async (req, res) => {
    try {
        let slug = req.params.id;
        const data = await Post.findById({ _id: slug });

        let addFavourite = true;
        console.log(data.createdAt); 
        // Check if user is logged in
        if (req.userId) {
            // Fetch the user information
            const user = await User.findById(req.userId);
            if (user && user.favourites.some(fav => fav.equals(mongoose.Types.ObjectId(slug)))) {
                addFavourite = false;
            }
        }

        const locals = {
            title: "RE | Readable",
            description: "eCommerce for used books",
            addFavourite: addFavourite
        };

        res.render('books', {
            locals,
            data,
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});


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

// Helper function for rendering views with messages
const renderWithMessages = (res, view, messages, showRegisterForm, email = '', username = '') => {
    res.render(view, {
        messages: messages,
        showRegisterForm: showRegisterForm,
        email: email || '',
        username: username || ''
    });
};

// Helper function for validating email and password
const isValidEmail = (email) => {
    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    return emailPattern.test(email);
};

const isValidPassword = (password) => {
    const minLength = 6;
    const maxLength = 20;
    const specialCharRegex = /[!@#$%^&*(),.?":{}|<>]/;

    return (
        typeof password === 'string' &&
        password.length >= minLength &&
        password.length <= maxLength &&
        specialCharRegex.test(password)
    );
};

router.get('/account', (req, res) => {
    if (req.cookies.token) {
        return res.redirect('/dashboard');
    }
    return renderWithMessages(res, 'register', req.flash(), true);
});

router.post('/account', async (req, res) => {
    console.log("Form submitted:", req.body);
    const { action } = req.body;
    console.log("Action submitted:", action);
    // Common validation logic
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
            // Retrieve user records
            const user = await User.findOne({ email });
            const isPasswordValid = user && await bcrypt.compare(password, user.password);
            
            // Check if user exists and password is valid
            if (!isPasswordValid) {
                req.flash('error', 'Invalid email or password');
                return renderWithMessages(res, 'register', req.flash(), false, email);
            }
            // Check if user is verified
            if (!user.verified) {
                await verifyUser(req, { _id: user._id, email: user.email }, res);
                req.flash('success', 'Please verify your email address');
                return res.redirect('/otpvalidation');
            }
            // Generate JWT token
            const token = jwt.sign({ userId: user._id }, jwtSecret);
            res.cookie('token', token, { httpOnly: true });
            return res.redirect('/dashboard');
        } 
        else if (action === 'register') {
            console.log("Entering registration logic...");
            if (password !== confirmPassword) {
                req.flash('error', 'Passwords do not match');
                return renderWithMessages(res, 'register', req.flash(), true, email, username);
            }

            // Password validation
            if (!isValidPassword(password)) {
                req.flash('error', 'Password must be 6-20 chars and contain at least one special character');
                return renderWithMessages(res, 'register', req.flash(), true, email, username);
            }

            console.log("Validations passed, checking for existing email/username...");

            // Retrieve user records
            const emailExists = await User.findOne({ email });
            const usernameExists = await User.findOne({ username });

            // Check if email already exists
            if (emailExists) {
                req.flash('error', 'Email already registered');
                return renderWithMessages(res, 'register', req.flash(), true, '', username);
            }

            // Check if username already exists
            if (usernameExists) {
                req.flash('error', 'Username already exists');
                return renderWithMessages(res, 'register', req.flash(), true, email, '');
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Create the user
            const user = await User.create({
                email,
                username: username.trim(),
                password: hashedPassword,
                verified: false,
                image: '../../public/images/default.jpg'
            });
            
            console.log("User created:", user);

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

// OTP Validation - GET
router.get('/otpvalidation', (req, res) => {
    const { userId, email, reset_request } = req.session;

    if (!userId || !email) {
        req.flash('error', 'Unauthorized access. Please register or log in.');
        return res.redirect('/account');
    }

    res.render('auth/otpvalidation', {
        messages: req.flash(),
        email: censorEmail(email),
        userId,
        reset_request: Boolean(reset_request)
    });
});

// OTP Validation - POST
router.post('/otpvalidation', async (req, res) => {
    const { userId, otp } = req.body;
    const email = req.session.email;
    const resetRequest = req.session.reset_request || false;

    if (!userId || !otp) {
        req.flash('error', 'OTP is required');
        return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
    }

    try {
        const userOTPRecords = await UserOTPVerification.find({ userId });

        if (userOTPRecords.length === 0) {
            req.flash('error', 'Account record does not exist or has already been verified');
            return renderWithMessages(res, 'register', req.flash(), false);
        }

        const { expiresAt, otp: hashedOTP } = userOTPRecords[0];

        if (expiresAt < new Date()) {
            await UserOTPVerification.deleteMany({ userId });
            req.flash('error', 'OTP has expired');
            return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
        }

        const isOTPValid = await bcrypt.compare(otp.join(''), hashedOTP);
        if (!isOTPValid) {
            req.flash('error', 'Invalid OTP');
            return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
        }

        await UserOTPVerification.deleteMany({ userId });

        if (resetRequest) {
            // Set flag to allow access to change password without auth middleware
            req.session.passwordResetAllowed = true;
            req.session.email = email;
            req.session.userId = userId;
            req.flash('success', 'OTP verified successfully. Please reset your password.');
            return res.redirect('/change_password');  // Redirect to change_password
        }

        await User.updateOne({ _id: userId }, { verified: true });
        req.flash('success', 'Account verified successfully. Please log in.');
        return renderWithMessages(res, 'register', req.flash(), false);
    } catch (error) {
        console.error(error);
        req.flash('error', 'An error occurred. Please try again.');
        return res.render('auth/otpvalidation', { messages: req.flash(), email, userId });
    }
});

// Reset Password - GET
router.get('/reset_password', (req, res) => {
    res.render('auth/reset_password');
});

// Reset Password - POST
router.post('/reset_password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        req.flash('error', 'Email is required');
        return res.render('auth/reset_password', { messages: req.flash() });
    }

    try {
        const user = await User.findOne({ email });
        
        if (!user) {
            req.flash('error', 'No account found with that email');
            return res.render('auth/reset_password', { messages: req.flash() });
        }

        await sendOTPVerificationEmail(req, { _id: user._id, email }, res);
        req.session.reset_request = true;
        req.session.userId = user._id;
        req.session.email = email;
        res.render('auth/otpvalidation', { email: censorEmail(email), userId: user._id, reset_request: true });
    } catch (error) {
        console.error(error);
        req.flash('error', 'An error occurred');
        res.render('auth/reset_password', { messages: req.flash() });
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

// Change Password - GET
router.get('/change_password', (req, res) => {
    if (req.session.passwordResetAllowed) {
        // Render password reset form if allowed by session flag
        console.log("Change password (reset flow) request...");
        const email = req.session.email;
        const userId = req.session.userId;
        console.log("Email: ", email);
        console.log("User ID: ", userId);
        req.flash('success', 'Please enter your new password');
        return res.render('auth/change_password', { messages: req.flash() });
    }
    // Otherwise, enforce authMiddleware
    authMiddleware(req, res, () => {
        console.log("Change password (logged-in user) request...");
        res.render('auth/change_password');
    });
});


// Change Password - POST
router.post('/change_password', async (req, res) => {
    const { password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        req.flash('error', 'Passwords do not match');
        return res.render('auth/change_password', { messages: req.flash() });
    }

    if (!isValidPassword(password)) {
        req.flash('error', 'Password must be 6-20 chars and contain at least one special character');
        return res.render('auth/change_password', { messages: req.flash() });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Update the password for the user from session
        const userId = req.userId || req.session.userId;
        const email = req.session.email;

        console.log("User ID: ", userId);
        console.log("Email: ", email);
        await User.updateOne({ _id: userId }, { password: hashedPassword });
        
        // Clear the reset session flag and redirect based on the flow
        req.session.passwordResetAllowed = false;
        req.flash('success', 'Password reset successfully. Please log in.');

        if (req.session.reset_request) {
            delete req.session.reset_request;
        }
        console.log("Password: ", password);
        console.log("Password hashed: ", hashedPassword);
        return res.redirect('/account');
    } catch (error) {
        console.error(error);
        req.flash('error', 'An error occurred');
        return res.render('auth/change_password', { messages: req.flash() });
    }
});


router.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        const posts = await Post.find({ 'owner': user.username });
        const locals = {
            title: "Dashboard",
            description: "eCommerce for used books",
            user: user,
            posts: posts,
            currentPage: 'account'
        }
        res.render('user/dashboard', { 
            locals, 
        });
    } catch (error) {
        console.log(error)
    }

});


router.get('/add-favourite/:id', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        let slug = req.params.id;
        
        const favourites = Array.isArray(user.favourites) ? user.favourites : [];
        const book = await Post.findById(slug); // Assuming you have a Book model

        // If book owner is the same as the user, return an error message
        if (book.owner === user.username) {
            req.flash('error', 'You cannot add your own book to favourites');
        } 
        // If book is already in favourites, return an error message
        else if (favourites.includes(slug)) {
            req.flash('error', 'Book already in favourites');
        }
        // Otherwise, add the book to favourites
        else {
            await User.findByIdAndUpdate(req.userId, { $push: { favourites: slug } }, { new: true });
            req.flash('success', 'Book added to favourites');
        }
        return res.redirect(`/books/${slug}`);
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});





router.get('/user/favourites', authMiddleware, async (req, res) => {
    try {
        let perPage = 24;
        let page = parseInt(req.query.page) || 1;

        // Get the user by their ID
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).send("User not found");
        }

        // Use favourites directly if they are already ObjectIds
        const favourites = user.favourites;

        // Get the total count of favourites
        const count = favourites.length;

        // Pagination logic
        const startIndex = (page - 1) * perPage;
        const paginatedFavourites = favourites.slice(startIndex, startIndex + perPage);

        // Fetch the favourite posts from the database
        const data = await Post.find({ _id: { $in: paginatedFavourites } })
            .sort({ createdAt: -1 })  // Sort by creation date
            .skip(startIndex)
            .limit(perPage)
            .exec();

        const hasNextPage = page < Math.ceil(count / perPage);
        const hasPreviousPage = page > 1;
        const lastPage = Math.ceil(count / perPage);

        let addFavourite = true;

        // Check if user is logged in
        if (req.userId) {
            // Fetch the user information
            const user = await User.findById(req.userId);
            if (user && user.favourites.some(fav => fav.equals(mongoose.Types.ObjectId(slug)))) {
                addFavourite = false;
            }
        }
        
        const locals = {
            title: "Favourites",
            description: "eCommerce for used books",
            user: user,
            posts: data,
            addFavourite: addFavourite
        };

        res.render('user/favourites', {
            locals,
            data,
            count,
            truncateString,
            perPage,
            current: page,
            nextPage: hasNextPage ? page + 1 : null,
            previousPage: hasPreviousPage ? page - 1 : null,
            lastPage
        });
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});



module.exports = router;