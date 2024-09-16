require('dotenv').config();

const express = require('express');
const path = require('path');
const expressLayout = require('express-ejs-layouts');
const flash = require('connect-flash');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');

const connectDB = require('./server/config/db');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to DB
connectDB();

app.use(express.urlencoded({ extended:true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'aadam19',
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(flash());

app.use((req, res, next) => {
    res.locals.messages = req.flash();
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Templating Engine
app.use(expressLayout);
app.set('layout', './layouts/main');
app.set('view engine', 'ejs');

app.use('/', require('./server/routes/main'));

app.listen(PORT, () => {
    console.log(`App listening on port ${PORT}`);
});