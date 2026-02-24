// ==================== MODULE IMPORTS ====================
const fs = require('fs');
const path = require('path');
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const cors = require('cors');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const validator = require('validator');
const http = require('http');
const socketIo = require('socket.io');
const axios = require('axios');
require('dotenv').config();
const Groq = require('groq-sdk');
const mysql = require('mysql2/promise');

// ==================== APP & SERVER SETUP ====================
const newapp2 = express();
const server = http.createServer(newapp2);
const io = socketIo(server);

// ==================== DATABASE POOL ====================
const db = mysql.createPool({
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: Number(process.env.DB_PORT),
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

db.query('SELECT 1')
    .then(() => console.log('✅ Database Connected!'))
    .catch(err => console.error('❌ DB Connection Error:', err.message));

// ==================== MAIL TRANSPORTER ====================
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'ibarealestate2023@gmail.com',
        pass: process.env.EMAIL_PASS
    }
});

// ==================== MULTER FILE UPLOAD ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'uploads/';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// ==================== CORE MIDDLEWARE ====================
newapp2.use(cors());
newapp2.use(express.json());
newapp2.use(express.urlencoded({ extended: true }));
newapp2.use(bodyParser.json({ limit: '50mb' }));
newapp2.use(bodyParser.urlencoded({ limit: '50mb', extended: true, parameterLimit: 1000000 }));
newapp2.use(cookieParser());

// ==================== SESSION ====================
newapp2.use(session({
    secret: process.env.SESSION_SECRET || 'lateef.2008',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// ==================== PASSPORT ====================
newapp2.use(passport.initialize());
newapp2.use(passport.session());

passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    async (email, password, done) => {
        try {
            const [results] = await db.query('SELECT * FROM signin WHERE email = ?', [email]);
            if (results.length === 0) return done(null, false, { message: 'Invalid credentials' });
            const user = results[0];
            const match = bcrypt.compareSync(password, user.confirmPassword);
            if (!match) return done(null, false, { message: 'Invalid credentials' });
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [results] = await db.query('SELECT * FROM signin WHERE id = ?', [id]);
        done(null, results[0] || false);
    } catch (err) {
        done(err);
    }
});

// ==================== STATIC FILES ====================
newapp2.set('views', path.join(__dirname, 'views'));
newapp2.set('view engine', 'ejs');
newapp2.use('/img', express.static(path.join(__dirname, 'public', 'img')));
newapp2.use('/css', express.static(path.join(__dirname, 'public', 'css')));
newapp2.use('/plugins', express.static(path.join(__dirname, 'public', 'plugins')));
newapp2.use('/dist', express.static(path.join(__dirname, 'public', 'dist')));
newapp2.use('/js', express.static(path.join(__dirname, 'public', 'js')));
newapp2.use('/data', express.static(path.join(__dirname, 'public', 'data')));
newapp2.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==================== AUTH MIDDLEWARE ====================
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

function requireAgent(req, res, next) {
    if (req.session && req.session.role === 'agent' && req.session.userId) {
        return next();
    }
    console.warn('Unauthorized agent access attempt:', req.session);
    res.status(401).json({ error: 'Unauthorized: Please log in as an agent' });
}

function requireAdmin(req, res, next) {
    if (req.user && req.user.email === process.env.ADMIN_EMAIL) {
        return next();
    }
    res.status(403).send('Forbidden: Admin access required');
}

// ==================== GROQ AI ====================
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
    socket.on('joinChat', (userId) => {
        socket.join(String(userId));
        console.log(`User ${userId} joined chat room`);
    });

    socket.on('sendMessage', async ({ senderId, receiverId, message }) => {
        try {
            const [result] = await db.query(
                'INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
                [senderId, receiverId, message]
            );
            const timestamp = new Date();
            socket.emit('messageSent', { message, timestamp });
            io.to(String(receiverId)).emit('receiveMessage', { message, senderId, timestamp });
        } catch (err) {
            console.error('Socket sendMessage DB error:', err);
            socket.emit('messageError', { error: 'Failed to send message' });
        }
    });
});

// ==================== HELPER: ADMIN EMAIL ====================
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'ibarealestate2023@gmail.com';

// ==================== API ROUTES ====================

// Check login status
newapp2.get('/api/check-login', (req, res) => {
    if (req.user) {
        res.json({ loggedIn: true, username: req.user.firstName });
    } else {
        res.json({ loggedIn: false });
    }
});

// ==================== PUBLIC PAGES ====================

// Home / Website
newapp2.get('/', async (req, res) => {
    try {
        const [card] = await db.query('SELECT * FROM all_properties LIMIT 3');
        res.render('website', { card });
    } catch (err) {
        console.error('GET / error:', err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/website', async (req, res) => {
    try {
        const [card] = await db.query('SELECT * FROM all_properties LIMIT 3');
        res.render('website', { card });
    } catch (err) {
        console.error('GET /website error:', err.message);
        res.status(500).send('Server error');
    }
});

// Login page
newapp2.get('/login', (req, res) => res.render('login'));

// Forgot password page
newapp2.get('/forgot-password.html', (req, res) => res.render('forgotten-password'));

// Register page
newapp2.get('/register.html', (req, res) => res.render('signin-page'));

// Misc redirect routes
newapp2.get('/invalid-reg-details', (req, res) => res.render('signin-page'));
newapp2.get('/valid-reg-details', (req, res) => res.render('login'));
newapp2.get('/already-have-acct', (req, res) => res.render('login'));
newapp2.get('/invalid-login', (req, res) => res.render('login'));
newapp2.get('/property-detail.html', (req, res) => res.render('login'));

// ==================== REGISTER (POST /submit) ====================
newapp2.post('/submit', async (req, res) => {
    const { firstName, middleName, lastName, email, phone, confirmPassword } = req.body;

    // Validate email format
    if (!email || !validator.isEmail(email)) {
        return res.status(400).render('invalid-email', {
            error: 'Please provide a valid email address'
        });
    }

    // Validate required fields
    if (!firstName || !lastName || !phone || !confirmPassword) {
        return res.status(400).render('invalid-email', {
            error: 'All required fields must be filled in'
        });
    }

    try {
        // Check for duplicate email
        const [existing] = await db.query(
            'SELECT COUNT(*) AS count FROM signin WHERE email = ?',
            [email]
        );
        if (existing[0].count > 0) {
            return res.render('invalid-email', { error: 'This email is already registered' });
        }

        // Hash password and insert user
        const hashedPassword = bcrypt.hashSync(confirmPassword, 10);
        await db.query(
            'INSERT INTO signin (firstName, middleName, lastName, email, phone, confirmPassword, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [firstName, middleName || null, lastName, email, phone, hashedPassword, 'user']
        );

        // Send welcome email (non-blocking)
        const mailOptions = {
            from: process.env.EMAIL_USER || ADMIN_EMAIL,
            to: email,
            subject: 'Welcome to G.O Aregban Real Estate Firm',
            html: `
                <!DOCTYPE html>
                <html>
                <body style="font-family:'DM Sans',Arial,sans-serif;background:#faf7f2;margin:0;padding:32px 16px;">
                    <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 8px 32px rgba(13,33,55,0.12);">
                        <div style="background:linear-gradient(135deg,#0d2137,#1e4a78);padding:36px 32px;text-align:center;">
                            <h1 style="font-family:Georgia,serif;color:#e0aa45;font-size:1.8rem;margin:0 0 8px;">Welcome Aboard! 🎉</h1>
                            <p style="color:rgba(255,255,255,0.7);font-size:0.85rem;margin:0;">G.O Aregban Real Estate Firm & Consultant</p>
                        </div>
                        <div style="padding:36px 32px;">
                            <p style="color:#0d2137;font-size:1rem;font-weight:600;margin:0 0 14px;">Dear ${firstName} ${lastName},</p>
                            <p style="color:#475569;font-size:0.875rem;line-height:1.8;margin:0 0 16px;">
                                Thank you for creating an account with <strong style="color:#0d2137;">G.O Aregban Real Estate Firm</strong>.
                                We're thrilled to have you join thousands of buyers, renters, and investors who trust us to find their perfect property across Nigeria.
                            </p>
                            <p style="color:#475569;font-size:0.875rem;line-height:1.8;margin:0 0 28px;">
                                You can now sign in to explore exclusive property listings, save favourites, and get in touch with our team of licensed estate surveyors.
                            </p>
                            <div style="text-align:center;margin-bottom:28px;">
                                <a href="${process.env.SITE_URL || 'http://localhost:10000'}/"
                                   style="display:inline-block;padding:14px 36px;background:linear-gradient(135deg,#0d2137,#1e4a78);color:#fff;text-decoration:none;border-radius:10px;font-weight:700;font-size:0.9rem;">
                                    Sign In to Continue →
                                </a>
                            </div>
                            <p style="color:#94a3b8;font-size:0.78rem;text-align:center;margin:0;">If you did not create this account, please ignore this email.</p>
                        </div>
                        <div style="background:#f1f5f9;padding:18px 32px;text-align:center;">
                            <p style="color:#94a3b8;font-size:0.72rem;margin:0;">
                                © 2025 G.O AREGBAN REAL ESTATE FIRM. All rights reserved.<br>
                                NIESV Member Firm · ESVARBON Licensed
                            </p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) console.error('Welcome email error:', error);
            else console.log('Welcome email sent:', info.response);
        });

        console.log(`✅ User registered: ${email}`);

        // Redirect back to home with popup trigger params
        return res.redirect(`/?registered=true&name=${encodeURIComponent(firstName)}`);

    } catch (err) {
        console.error('Registration error:', err.message);
        return res.status(500).send('Server error');
    }
});

// ==================== LOGIN (POST /dashboard) ====================
newapp2.post('/dashboard', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.render('invalid-login');
    }

    try {
        const [results] = await db.query('SELECT * FROM signin WHERE email = ?', [email]);

        if (results.length === 0 || !bcrypt.compareSync(password, results[0].confirmPassword)) {
            console.log('Invalid login attempt for:', email);
            return res.render('invalid-login');
        }

        const user = results[0];

        req.login(user, async (err) => {
            if (err) {
                console.error('req.login error:', err);
                return res.status(500).send('Login error');
            }

            // ── Admin login ──────────────────────────────────
            if (email === ADMIN_EMAIL) {
                req.session.isAdmin = true;
                req.session.isAgent = false;
                req.session.role = 'admin';
                return res.render('valid-login', {
                    username: user.firstName,
                    surname: user.lastName,
                    isAdmin: true,
                    isAgent: false
                });
            }

            // ── Agent login ──────────────────────────────────
            if (user.role === 'agent') {
                req.session.isAgent = true;
                req.session.isAdmin = false;
                req.session.userId = user.id;
                req.session.role = 'agent';
                req.session.firstName = user.firstName;
                req.session.lastName = user.lastName;

                const agentId = user.id;
                try {
                    const [
                        [totalPropsRows],
                        [totalAgentsRows],
                        [pendingRows],
                        [soldRows],
                        [activities],
                        [agents],
                        [approvals],
                        [customers],
                        [soldProps],
                        [settings]
                    ] = await Promise.all([
                        db.query(`
                            SELECT COUNT(*) AS totalProperties FROM (
                                SELECT id FROM all_properties WHERE agentId = ?
                                UNION
                                SELECT id FROM sold_properties WHERE agentId = ?
                                UNION
                                SELECT id FROM sales_approval WHERE agentId = ?
                            ) AS combined`, [agentId, agentId, agentId]),
                        db.query(`SELECT COUNT(*) AS totalAgents FROM signin WHERE role = 'agent'`),
                        db.query(`SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`, [agentId]),
                        db.query(`SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`, [agentId]),
                        db.query(`SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`, [agentId]),
                        db.query(`SELECT id, firstName, lastName, email, phone FROM signin WHERE id = ?`, [agentId]),
                        db.query(`SELECT s.id, s.title, s.status, u.firstName AS agentName FROM sales_approval s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ? AND s.status = 'pending'`, [agentId]),
                        db.query(`SELECT firstName, lastName, email, phone, role FROM signin WHERE role = 'user' LIMIT 10`),
                        db.query(`SELECT s.title, u.firstName AS agentName, s.amount, s.created_at AS soldDate FROM sold_properties s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ?`, [agentId]),
                        db.query(`SELECT 'G.O Aregban Real Estate' AS siteTitle, ? AS adminEmail`, [ADMIN_EMAIL])
                    ]);

                    return res.render('agent-dashboard', {
                        totalProperties: totalPropsRows[0].totalProperties,
                        totalAgents: totalAgentsRows[0].totalAgents,
                        pendingApprovals: pendingRows[0].pendingApprovals,
                        soldProperties: soldRows[0].soldProperties,
                        activities, agents, approvals, customers, soldProps,
                        siteTitle: settings[0].siteTitle,
                        adminEmail: settings[0].adminEmail,
                        username: user.firstName,
                        surname: user.lastName,
                        isAdmin: false,
                        isAgent: true
                    });
                } catch (dataErr) {
                    console.error('Agent dashboard data fetch error:', dataErr);
                    return res.status(500).send('Server error loading agent dashboard');
                }
            }

            // ── Regular user login ───────────────────────────
            req.session.isAdmin = false;
            req.session.isAgent = false;
            req.session.role = 'user';
            try {
                const [card] = await db.query('SELECT * FROM all_properties LIMIT 3');
                return res.render('website', { card });
            } catch (cardErr) {
                console.error('Website load error:', cardErr.message);
                return res.status(500).send('Server error');
            }
        });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).send('Server error');
    }
});

// ==================== NAVIGATION ROUTES ====================

newapp2.get('/valid-login', ensureAuthenticated, (req, res) => {
    res.redirect('/track-sales.html');
});

newapp2.get('/index.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM all_properties');
        res.render('index', { card, isAdmin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/buy-page.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query("SELECT * FROM all_properties WHERE rentSell = 'sell'");
        res.render('buy-page', { card, isAdmin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/home-improvemet-page.html', ensureAuthenticated, (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    res.render('home-improvemet-page', { isAdmin });
});

newapp2.get('/sell-page.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM all_properties');
        res.render('sell-page', { card, isAdmin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/rent-page.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query("SELECT * FROM all_properties WHERE rentSell = 'rent'");
        res.render('rent-page', { card, isAdmin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/message-page.html', ensureAuthenticated, (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    res.render('message-page', { isAdmin });
});

newapp2.get('/setting-page.html', ensureAuthenticated, (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    res.render('setting-page', { isAdmin });
});

newapp2.get('/sales-approval.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM sales_approval');
        res.render('sales-approval', { card, isAdmin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/notificatin-page.html', ensureAuthenticated, (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    res.render('notification-page', { isAdmin });
});

newapp2.get('/tour-requested.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [results] = await db.query('SELECT *, (SELECT COUNT(*) FROM request_tour) AS count FROM request_tour');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('requested-tour', { card: results, rowCount, isAdmin });
    } catch (err) {
        console.error('Tour requests fetch error:', err.message);
        res.status(500).send('Database query error.');
    }
});

newapp2.get('/profile-page.html', ensureAuthenticated, async (req, res) => {
    if (!req.user || !req.user.id) return res.redirect('/login');
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [results] = await db.query(
            'SELECT id, firstName, middleName, lastName, email, phone FROM signin WHERE id = ?',
            [req.user.id]
        );
        if (results.length === 0) return res.status(404).send('User not found');
        const u = results[0];
        res.render('profile-page', {
            id: u.id,
            firstName: u.firstName,
            middleName: u.middleName,
            lastName: u.lastName,
            email: u.email,
            phone: u.phone,
            isAdmin
        });
    } catch (err) {
        console.error('Profile fetch error:', err);
        res.status(500).send('Internal Server Error');
    }
});

// ==================== TRACK SALES ====================
newapp2.get('/track-sales.html', ensureAuthenticated, async (req, res) => {
    try {
        const [
            [pendingRes],
            [allSalesRes],
            [soldRes],
            [customersRes],
            [soldMonthRes],
            [propertyTypesRes],
            [monthlySoldRes]
        ] = await Promise.all([
            db.query('SELECT COUNT(*) AS count FROM sales_approval'),
            db.query('SELECT COUNT(*) AS count FROM all_properties'),
            db.query('SELECT COUNT(*) AS count FROM sold_properties'),
            db.query('SELECT COUNT(DISTINCT email) AS count FROM signin'),
            db.query("SELECT COUNT(*) AS count FROM sold_properties WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())"),
            db.query("SELECT `property-type` AS type, COUNT(*) AS count FROM all_properties WHERE `property-type` IN ('Plots of Land', 'Duplex/Bangalow/Storey building', 'Self Contain') GROUP BY `property-type`"),
            db.query("SELECT DATE_FORMAT(created_at, '%b %Y') AS month, COUNT(*) AS count FROM sold_properties WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH) GROUP BY DATE_FORMAT(created_at, '%Y-%m') ORDER BY DATE_FORMAT(created_at, '%Y-%m') ASC")
        ]);

        const stats = {
            pendingSales: pendingRes[0].count || 0,
            allSales: allSalesRes[0].count || 0,
            soldProperties: soldRes[0].count || 0,
            customers: customersRes[0].count || 0,
            soldThisMonth: soldMonthRes[0].count || 0,
            propertyTypes: propertyTypesRes,
            monthlySold: monthlySoldRes.map(row => ({
                month: row.month,
                count: parseInt(row.count) || 0
            }))
        };

        res.render('sales-tracker', { stats, isAdmin: true });
    } catch (err) {
        console.error('Track sales error:', err.message);
        res.status(500).send('Server error loading track sales');
    }
});

// ==================== PROPERTY UPLOAD ====================
newapp2.post('/upload', ensureAuthenticated, upload.fields([
    { name: 'image', maxCount: 10 },
    { name: 'video', maxCount: 5 }
]), async (req, res) => {
    const userId = req.user.id;
    try {
        const [results] = await db.query('SELECT role FROM signin WHERE id = ?', [userId]);
        if (results.length === 0) return res.status(404).send('User not found');

        const imagePaths = req.files && req.files.image ? req.files.image.map(f => f.path).join(',') : '';
        const videoPaths = req.files && req.files.video ? req.files.video.map(f => f.path).join(',') : '';
        const {
            ownerName, ownerEmail, ownerPhone, propertyAddress,
            bedrooms, bathrooms, sqft, description, title,
            rentSell, amount, property_type
        } = req.body;

        await db.query(
            `INSERT INTO sales_approval 
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft, image_data, video, description, title, rentSell, amount, property_type, agentId) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft,
             imagePaths, videoPaths, description, title, rentSell, amount, property_type, userId]
        );

        res.json({ success: true, message: 'Property uploaded successfully! Your listing has been submitted for review.' });
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Error uploading property: ' + err.message });
    }
});

// ==================== SALES ROUTES ====================
newapp2.get('/sales-completed', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM all_properties');
        res.render('sell-page', { card, isAdmin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/sales-approved', ensureAuthenticated, (req, res) => {
    res.redirect('/sales-approval.html');
});

newapp2.get('/sales-declined', ensureAuthenticated, (req, res) => {
    res.redirect('/sales-approval.html');
});

// ==================== REQUEST TOUR ====================
newapp2.get('/request-tour', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM all_properties WHERE id = ?', [propertyId]);
        if (card.length === 0) return res.status(404).send('No property found with that ID.');
        res.render('request-tour', {
            property: card[0],
            isAdmin,
            userId: req.user.id,
            userEmail: req.user.email
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/view', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM sales_approval WHERE id = ?', [propertyId]);
        if (card.length === 0) return res.status(404).send('No property found with that ID.');
        res.render('request-tour', {
            property: card[0],
            isAdmin,
            userId: req.user.id,
            userEmail: req.user.email
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.post('/submit-tour', async (req, res) => {
    const { name, email, phone, date, time } = req.body;
    try {
        await db.query(
            'INSERT INTO request_tour (name, email, phone, date, time) VALUES (?, ?, ?, ?, ?)',
            [name, email, phone, date, time]
        );
        res.render('tour-submitted');
    } catch (err) {
        console.error('Submit tour error:', err);
        res.status(500).send('Error inserting data: ' + err);
    }
});

newapp2.get('/tour-submitted', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [card] = await db.query('SELECT * FROM all_properties');
        res.render('index', { card, isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ==================== HOME IMPROVEMENT ====================
newapp2.post('/improvement-request-form', async (req, res) => {
    const { name, email, phone, message } = req.body;
    try {
        await db.query(
            'INSERT INTO homeImprovement (name, email, phone, message) VALUES (?, ?, ?, ?)',
            [name, email, phone, message]
        );
        res.render('tour-submitted');
    } catch (err) {
        console.error('Improvement form error:', err);
        res.status(500).send('Error inserting data: ' + err);
    }
});

// ==================== PROFILE ====================
newapp2.get('/edit-profile', ensureAuthenticated, (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    res.render('setting-page', { isAdmin });
});

newapp2.post('/update-profile', ensureAuthenticated, async (req, res) => {
    const { firstName, middleName, lastName, email, phone, currentPassword } = req.body;
    const userId = req.user.id;
    try {
        const [results] = await db.query('SELECT confirmPassword FROM signin WHERE id = ?', [userId]);
        if (results.length === 0) return res.status(404).send('User not found');

        if (!bcrypt.compareSync(currentPassword, results[0].confirmPassword)) {
            return res.status(401).send('Current password is incorrect');
        }

        await db.query(
            'UPDATE signin SET firstName = ?, middleName = ?, lastName = ?, email = ?, phone = ? WHERE id = ?',
            [firstName, middleName || null, lastName, email, phone, userId]
        );
        res.redirect('/profile-page.html');
    } catch (err) {
        console.error('Update profile error:', err);
        res.status(500).send('Error updating profile');
    }
});

// ==================== MESSAGING ====================
newapp2.post('/message', ensureAuthenticated, async (req, res) => {
    const message = req.body.message;
    if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'Invalid message format' });
    }
    const userId = req.user.id;
    try {
        const [results] = await db.query('SELECT firstName, email FROM signin WHERE id = ?', [userId]);
        if (results.length === 0) return res.status(404).json({ error: 'User not found' });

        const user = results[0];
        const mailOptions = {
            from: user.email,
            to: ADMIN_EMAIL,
            subject: `New Message from ${user.firstName}`,
            text: message,
            html: `<p><strong>From:</strong> ${user.firstName} (${user.email})</p><p><strong>Message:</strong></p><p>${message}</p>`
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) {
                console.error('Message email error:', err);
                return res.status(500).json({ error: 'Failed to send message' });
            }
            res.status(200).json({ success: true, message: 'Message sent successfully' });
        });
    } catch (err) {
        console.error('Message route DB error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== SALES APPROVAL / DECLINE ====================
newapp2.get('/approve', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');

    try {
        const [results] = await db.query('SELECT * FROM sales_approval WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.status(404).send('No property found with that ID.');

        const p = results[0];
        await db.query(
            `INSERT INTO all_properties 
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft, image_data, video, description, title, rentSell, agentId, amount, \`property-type\`, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')`,
            [p.ownerName, p.ownerEmail, p.ownerPhone, p.propertyAddress,
             p.bedrooms, p.bathrooms, p.sqft, p.image_data,
             p.video, p.description, p.title, p.rentSell,
             p.agentId, p.amount, p.property_type]
        );
        await db.query('INSERT INTO total_amount (amount) VALUES (?)', [p.amount]);
        await db.query('DELETE FROM sales_approval WHERE id = ?', [propertyId]);
        res.render('sales-approved-successfully');
    } catch (err) {
        console.error('Approve property error:', err.message);
        res.status(500).send('Error processing approval: ' + err.message);
    }
});

newapp2.get('/decline', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');

    try {
        const [results] = await db.query('SELECT * FROM sales_approval WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.status(404).send('No property found with that ID.');
        await db.query('DELETE FROM sales_approval WHERE id = ?', [propertyId]);
        res.render('sales-declined-successfully');
    } catch (err) {
        console.error('Decline property error:', err.message);
        res.status(500).send('Error processing decline: ' + err.message);
    }
});

// ==================== CUSTOMERS ====================
newapp2.get('/view-customers.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [results] = await db.query(
            'SELECT id, firstName, middleName, email, phone, (SELECT COUNT(*) FROM signin) AS count FROM signin'
        );
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('customers', {
            customers: results, rowCount, isAdmin,
            userId: req.user.id, userEmail: req.user.email
        });
    } catch (err) {
        console.error('Customers fetch error:', err);
        res.status(500).send('Database query error.');
    }
});

// ==================== TOUR APPROVAL ====================
newapp2.get('/approve-tour', ensureAuthenticated, async (req, res) => {
    const tourId = req.query.id;
    if (!tourId) return res.status(400).send('Tour ID is required.');
    try {
        const [results] = await db.query('SELECT * FROM request_tour WHERE id = ?', [tourId]);
        if (results.length === 0) return res.status(404).send('Tour not found.');

        const tour = results[0];
        const mailOptions = {
            from: process.env.EMAIL_USER || ADMIN_EMAIL,
            to: tour.email,
            subject: 'Tour Request Approved – G.O Aregban Real Estate',
            text: `Dear ${tour.name},\n\nYour tour request has been approved.\n\nBest regards,\nG.O Aregban Real Estate Team`
        };

        transporter.sendMail(mailOptions, async (error) => {
            if (error) {
                console.error('Tour approval email error:', error);
                return res.status(500).send('Error sending approval email.');
            }
            try {
                await db.query('DELETE FROM request_tour WHERE id = ?', [tourId]);
                res.render('tour-approved-successfully');
            } catch (err) {
                console.error('Tour delete error:', err);
                res.status(500).send('Database query error.');
            }
        });
    } catch (err) {
        console.error('Approve tour error:', err);
        res.status(500).send('Database query error.');
    }
});

newapp2.get('/decline-tour', ensureAuthenticated, async (req, res) => {
    const tourId = req.query.id;
    if (!tourId) return res.status(400).send('Tour ID is required.');
    try {
        const [results] = await db.query('SELECT * FROM request_tour WHERE id = ?', [tourId]);
        if (results.length === 0) return res.status(404).send('Tour not found.');

        const tour = results[0];
        const mailOptions = {
            from: process.env.EMAIL_USER || ADMIN_EMAIL,
            to: tour.email,
            subject: 'Tour Request Declined – G.O Aregban Real Estate',
            text: `Dear ${tour.name},\n\nWe regret to inform you that your tour request has been declined.\n\nBest regards,\nG.O Aregban Real Estate Team`
        };

        transporter.sendMail(mailOptions, async (error) => {
            if (error) {
                console.error('Tour decline email error:', error);
                return res.status(500).send('Error sending decline email.');
            }
            try {
                await db.query('DELETE FROM request_tour WHERE id = ?', [tourId]);
                res.render('tour-declined-successfully');
            } catch (err) {
                console.error('Tour delete error:', err);
                res.status(500).send('Database query error.');
            }
        });
    } catch (err) {
        console.error('Decline tour error:', err);
        res.status(500).send('Database query error.');
    }
});

newapp2.get('/tour-approved-successfully', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [results] = await db.query('SELECT *, (SELECT COUNT(*) FROM request_tour) AS count FROM request_tour');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('requested-tour', { card: results, isAdmin, userId: req.user.id, userEmail: req.user.email, rowCount });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Database query error.');
    }
});

newapp2.get('/tour-declined-successfully', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    try {
        const [results] = await db.query('SELECT *, (SELECT COUNT(*) FROM request_tour) AS count FROM request_tour');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('requested-tour', { card: results, rowCount, isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Database query error.');
    }
});

// ==================== SEARCH ====================
newapp2.get('/search', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    const { location, min_price, max_price, min_beds, min_baths } = req.query;

    let sql = 'SELECT * FROM all_properties WHERE 1=1';
    let values = [];

    if (location) { sql += ' AND propertyAddress LIKE ?'; values.push(`%${location}%`); }
    if (min_price && !isNaN(min_price)) { sql += ' AND amount >= ?'; values.push(Number(min_price)); }
    if (max_price && !isNaN(max_price)) { sql += ' AND amount <= ?'; values.push(Number(max_price)); }
    if (min_beds && !isNaN(min_beds)) { sql += ' AND bedrooms >= ?'; values.push(Number(min_beds)); }
    if (min_baths && !isNaN(min_baths)) { sql += ' AND bathrooms >= ?'; values.push(Number(min_baths)); }

    try {
        const [card] = await db.query(sql, values);
        res.render('index', { card, isAdmin });
    } catch (err) {
        console.error('Search error:', err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/buy-search-form', ensureAuthenticated, async (req, res) => {
    const isAdmin = req.user.email === ADMIN_EMAIL;
    const { location, min_price, max_price, min_beds, min_baths } = req.query;

    let query = "SELECT * FROM all_properties WHERE rentSell = 'sell'";
    let queryParams = [];

    if (location && location.trim()) { query += ' AND propertyAddress LIKE ?'; queryParams.push(`%${location}%`); }
    if (min_price && !isNaN(min_price)) { query += ' AND amount >= ?'; queryParams.push(parseInt(min_price)); }
    if (max_price && !isNaN(max_price)) { query += ' AND amount <= ?'; queryParams.push(parseInt(max_price)); }
    if (min_beds && !isNaN(min_beds)) { query += ' AND bedrooms >= ?'; queryParams.push(parseInt(min_beds)); }
    if (min_baths && !isNaN(min_baths)) { query += ' AND bathrooms >= ?'; queryParams.push(parseInt(min_baths)); }

    try {
        const [card] = await db.query(query, queryParams);
        res.render('buy-page', { card, isAdmin });
    } catch (err) {
        console.error('Buy search error:', err.message);
        res.status(500).send('Server error');
    }
});

// ==================== CUSTOMER-FACING PAGES ====================
newapp2.get('/customer-buy-page.html', async (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'sell'";
    let params = [];
    if (req.query.property_type && req.query.property_type !== 'all') {
        query += ' AND `property-type` = ?';
        params.push(req.query.property_type);
    }
    try {
        const [card] = await db.query(query, params);
        res.render('customer-buy-page', { card });
    } catch (err) {
        console.error('Customer buy page error:', err.message);
        res.status(500).send('Server error: Unable to fetch properties.');
    }
});

newapp2.get('/costumer-sell-page.html', async (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'Rent'";
    let params = [];
    if (req.query.property_type && req.query.property_type !== 'all') {
        query += ' AND `property-type` = ?';
        params.push(req.query.property_type);
    }
    try {
        const [card] = await db.query(query, params);
        res.render('costumer-sell-page', { card });
    } catch (err) {
        console.error('Customer sell page error:', err.message);
        res.status(500).send('Server error: Unable to fetch properties.');
    }
});

newapp2.get('/customer-rent-page.html', async (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'Rent'";
    let params = [];
    if (req.query.property_type && req.query.property_type !== 'all') {
        query += ' AND `property-type` = ?';
        params.push(req.query.property_type);
    }
    try {
        const [card] = await db.query(query, params);
        res.render('customer-rent-page', { card });
    } catch (err) {
        console.error('Customer rent page error:', err.message);
        res.status(500).send('Server error: Unable to fetch properties.');
    }
});

// ==================== PROPERTY DETAIL ====================
newapp2.get('/property-detail', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');

    try {
        const [userResults] = await db.query('SELECT role FROM signin WHERE id = ?', [req.user.id]);
        if (userResults.length === 0) return res.status(404).send('User not found.');
        const isAdmin = userResults[0].role === 'admin';

        let [propResults] = await db.query('SELECT * FROM all_properties WHERE id = ?', [propertyId]);
        if (propResults.length === 0) {
            [propResults] = await db.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId]);
        }
        if (propResults.length === 0) return res.status(404).send('No property found with that ID.');

        const property = propResults[0];
        let agent = null;
        if (property.agentId) {
            const [agentResults] = await db.query(
                "SELECT * FROM signin WHERE id = ? AND role = 'agent'",
                [property.agentId]
            );
            agent = agentResults.length > 0 ? agentResults[0] : null;
        }

        res.render('view-details', { property, isAdmin, userId: req.user.id, userEmail: req.user.email, agent });
    } catch (err) {
        console.error('Property detail error:', err);
        res.status(500).send('Database query error.');
    }
});

// ==================== CONTACT ====================
newapp2.post('/contact', ensureAuthenticated, (req, res) => {
    const { name, email, phone, subject, message } = req.body;
    if (!name || !email || !phone || !message) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
    }
    const mailOptions = {
        from: `"G.O Aregban Real Estate" <${process.env.EMAIL_USER || ADMIN_EMAIL}>`,
        to: ADMIN_EMAIL,
        subject: `Contact Form: ${subject || 'New Inquiry'}`,
        html: `
            <h2>New Contact Message from Website</h2>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Phone:</strong> ${phone}</p>
            <p><strong>Subject:</strong> ${subject || 'N/A'}</p>
            <p><strong>Message:</strong></p>
            <p>${message.replace(/\n/g, '<br>')}</p>
            <hr>
            <p><em>Submitted on ${new Date().toLocaleString()}.</em></p>
        `
    };
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Contact email error:', error);
            return res.status(500).json({ success: false, message: 'Failed to send email. Please try again later.' });
        }
        console.log('Contact email sent:', info.response);
        return res.status(200).json({ success: true, message: "Your message has been sent successfully! We'll get back to you soon." });
    });
});

newapp2.post('/detail-contact', ensureAuthenticated, async (req, res) => {
    const { name, email, phone, message, propertyId } = req.body;
    const userId = req.user.id;

    if (!name || !email || !phone || !message || !propertyId) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
    }

    try {
        const [propResults] = await db.query('SELECT agentId FROM all_properties WHERE id = ?', [propertyId]);
        if (propResults.length === 0) return res.status(404).json({ success: false, message: 'Property not found' });

        const agentId = propResults[0].agentId;
        let recipientEmail = ADMIN_EMAIL;
        let receiverId = null;

        if (agentId) {
            const [agentResults] = await db.query(
                "SELECT id, email FROM signin WHERE id = ? AND role = 'agent'",
                [agentId]
            );
            if (agentResults.length > 0 && agentResults[0].email) {
                recipientEmail = agentResults[0].email;
                receiverId = agentId;
            }
        }

        if (!receiverId) {
            const [adminResults] = await db.query('SELECT id FROM signin WHERE email = ?', [ADMIN_EMAIL]);
            if (adminResults.length === 0) return res.status(500).json({ success: false, message: 'Admin not found' });
            receiverId = adminResults[0].id;
        }

        const mailOptions = {
            from: `"G.O Aregban Real Estate" <${process.env.EMAIL_USER || ADMIN_EMAIL}>`,
            to: recipientEmail,
            subject: 'New Property Inquiry',
            html: `
                <h2>New Contact Message</h2>
                <p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Phone:</strong> ${phone}</p>
                <p><strong>Message:</strong></p>
                <p>${message.replace(/\n/g, '<br>')}</p>
                <hr>
                <p><em>Submitted on ${new Date().toLocaleString()}.</em></p>
            `
        };

        transporter.sendMail(mailOptions, async (error) => {
            if (error) {
                console.error('Detail contact email error:', error);
                return res.status(500).json({ success: false, message: 'Failed to send email. Please try again later.' });
            }
            try {
                await db.query(
                    'INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
                    [userId, receiverId, message]
                );
                res.redirect('/chat?success=Message sent! Redirecting to chat...');
            } catch (insertErr) {
                console.error('Chat save error:', insertErr);
                res.status(500).json({ success: false, message: 'Message sent via email, but chat save failed.' });
            }
        });
    } catch (err) {
        console.error('Detail contact error:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ==================== LOGOUT ====================
newapp2.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error('Logout error:', err);
        req.session.destroy((err2) => {
            if (err2) console.error('Session destroy error:', err2);
            res.clearCookie('connect.sid');
            res.redirect('/');
        });
    });
});

newapp2.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) console.error('Logout error:', err);
        req.session.destroy(() => {
            res.json({ success: true, message: 'Logged out successfully' });
        });
    });
});

// ==================== SOLD / UNSOLD / EDIT SOLD ====================
newapp2.get('/sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId || isNaN(propertyId)) {
        return res.redirect('/sell-page.html?error=Invalid property ID. Please try again.');
    }

    try {
        const [results] = await db.query('SELECT * FROM all_properties WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.redirect('/sell-page.html?error=Property not found.');

        const p = results[0];
        await db.query(
            `INSERT INTO sold_properties (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description, sqft, image_data, video, amount, title, rentSell, agentId, \`property-type\`) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [p.ownerName || '', p.ownerEmail || '', p.ownerPhone || '',
             p.propertyAddress || '', p.bedrooms || '0', p.bathrooms || '0',
             p.description || '', p.sqft || '0', p.image_data, p.video,
             p.amount || null, p.title || null, p.rentSell || null,
             p.agentId, p['property-type'] || null]
        );
        await db.query('DELETE FROM all_properties WHERE id = ?', [propertyId]);
        res.redirect(`/index.html?success=sold&title=${encodeURIComponent(p.title || '')}`);
    } catch (err) {
        console.error('Sold route error:', err);
        res.redirect('/sell-page.html?error=Failed to mark property as sold. Please try again.');
    }
});

newapp2.get('/sold-properties', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM sold_properties ORDER BY id DESC');
        res.render('sold-properties', { soldProperties: results, isAdmin: true });
    } catch (err) {
        console.error('Sold properties fetch error:', err);
        res.redirect('/sold-properties?error=Failed to load sold properties.');
    }
});

newapp2.get('/edit-sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sold-properties?error=Invalid property ID.');
    try {
        const [results] = await db.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.redirect('/sold-properties?error=Property not found.');
        res.render('edit-sold', { property: results[0], isAdmin: true });
    } catch (err) {
        console.error('Edit sold fetch error:', err);
        res.redirect('/login');
    }
});

newapp2.post('/update-sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.body.id;
    if (!propertyId) return res.redirect('/sold-properties?error=Invalid property ID.');

    const updates = {
        title: req.body.title || null,
        description: req.body.description || '',
        amount: req.body.amount || null,
        propertyAddress: req.body.propertyAddress || '',
        bedrooms: req.body.bedrooms || '0',
        bathrooms: req.body.bathrooms || '0',
        sqft: req.body.sqft || '0',
        ownerName: req.body.ownerName || '',
        ownerEmail: req.body.ownerEmail || '',
        ownerPhone: req.body.ownerPhone || '',
        rentSell: req.body.rentSell || null,
        property_type: req.body['property-type'] || null
    };

    try {
        await db.query(
            `UPDATE sold_properties SET title = ?, description = ?, amount = ?, propertyAddress = ?, bedrooms = ?, bathrooms = ?, sqft = ?, ownerName = ?, ownerEmail = ?, ownerPhone = ?, rentSell = ?, \`property-type\` = ? WHERE id = ?`,
            [updates.title, updates.description, updates.amount, updates.propertyAddress,
             updates.bedrooms, updates.bathrooms, updates.sqft, updates.ownerName,
             updates.ownerEmail, updates.ownerPhone, updates.rentSell, updates.property_type, propertyId]
        );
        res.redirect('/sold-properties?success=Property updated successfully!');
    } catch (err) {
        console.error('Update sold error:', err);
        res.redirect('/sold-properties?error=Failed to update property.');
    }
});

newapp2.post('/unsold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.body.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sold-properties?error=Invalid property ID.');

    try {
        const [results] = await db.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.redirect('/sold-properties?error=Property not found.');

        const p = results[0];
        await db.query(
            `INSERT INTO all_properties (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description, sqft, image_data, video, amount, title, rentSell, \`property-type\`, agentId) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [p.ownerName || '', p.ownerEmail || '', p.ownerPhone || '',
             p.propertyAddress || '', p.bedrooms || '0', p.bathrooms || '0',
             p.description || '', p.sqft || '0', p.image_data, p.video,
             p.amount || null, p.title || null, p.rentSell || null,
             p['property-type'] || null, p.agentId]
        );
        await db.query('DELETE FROM sold_properties WHERE id = ?', [propertyId]);
        res.redirect('/sold-properties?success=Property moved back to active sales!');
    } catch (err) {
        console.error('Unsold route error:', err);
        res.redirect('/sold-properties?error=Failed to move property back to sales.');
    }
});

newapp2.post('/delete-sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.body.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sold-properties?error=Invalid property ID.');
    try {
        const [result] = await db.query('DELETE FROM sold_properties WHERE id = ?', [propertyId]);
        if (result.affectedRows === 0) return res.redirect('/sold-properties?error=Property not found.');
        res.redirect('/sold-properties?success=Property deleted successfully!');
    } catch (err) {
        console.error('Delete sold error:', err);
        res.redirect('/sold-properties?error=Failed to delete property.');
    }
});

// ==================== MANAGE AGENTS ====================
newapp2.get('/manage-agent', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query(`
            SELECT 
                s.id, s.firstName, s.middleName, s.lastName, s.email, s.phone,
                COALESCE(stats.propertiesAdded, 0) AS propertiesAdded,
                COALESCE(stats.soldProperties, 0) AS soldProperties,
                COALESCE(stats.pendingProperties, 0) AS pendingProperties
            FROM signin s
            LEFT JOIN (
                SELECT agentId,
                    COUNT(*) AS propertiesAdded,
                    SUM(CASE WHEN status = 'sold' THEN 1 ELSE 0 END) AS soldProperties,
                    SUM(CASE WHEN status IN ('pending', 'approved') THEN 1 ELSE 0 END) AS pendingProperties
                FROM (
                    SELECT agentId, status FROM all_properties
                    UNION ALL
                    SELECT agentId, status FROM sold_properties
                    UNION ALL
                    SELECT agentId, status FROM sales_approval
                ) combined
                GROUP BY agentId
            ) stats ON s.id = stats.agentId
            WHERE s.role = 'agent'
        `);
        res.render('manage-agent', { agents: results, isAdmin: true });
    } catch (err) {
        console.error('Manage agents error:', err);
        res.status(500).send('Server error');
    }
});

newapp2.post('/manage/agent', ensureAuthenticated, async (req, res) => {
    const { firstName, middleName, lastName, email, phone } = req.body;
    if (!validator.isEmail(email)) return res.status(400).json({ error: 'Invalid email address' });

    try {
        const [existing] = await db.query('SELECT COUNT(*) AS count FROM signin WHERE email = ?', [email]);
        if (existing[0].count > 0) return res.status(400).json({ error: 'Email already exists' });

        const tempPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = bcrypt.hashSync(tempPassword, 10);
        await db.query(
            'INSERT INTO signin (firstName, middleName, lastName, email, phone, confirmPassword, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [firstName, middleName || null, lastName, email, phone || null, hashedPassword, 'agent']
        );

        const mailOptions = {
            from: process.env.EMAIL_USER || ADMIN_EMAIL,
            to: email,
            subject: 'Welcome to G.O Aregban Real Estate – Agent Account Created',
            html: `
                <h1>Welcome to G.O Aregban Real Estate!</h1>
                <p>Dear ${firstName} ${lastName},</p>
                <p>Your agent account has been created. Here are your login details:</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Temporary Password:</strong> ${tempPassword}</p>
                <p>Please log in and change your password immediately.</p>
                <p>Best regards,<br>G.O Aregban Real Estate Team</p>
            `
        };
        transporter.sendMail(mailOptions, (error) => {
            if (error) console.error('Agent welcome email error:', error);
        });
        res.json({ success: true, message: 'Agent added successfully! Login credentials sent via email.' });
    } catch (err) {
        console.error('Add agent error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

newapp2.put('/manage/agent/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    const { firstName, middleName, lastName, email, phone } = req.body;
    if (!validator.isEmail(email)) return res.status(400).send('Invalid email address');
    try {
        await db.query(
            'UPDATE signin SET firstName = ?, middleName = ?, lastName = ?, email = ?, phone = ? WHERE id = ? AND role = "agent"',
            [firstName, middleName || null, lastName, email, phone || null, id]
        );
        res.send('Agent updated successfully');
    } catch (err) {
        console.error('Update agent error:', err);
        res.status(500).send('Server error');
    }
});

newapp2.delete('/manage/agent/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM signin WHERE id = ? AND role = "agent"', [id]);
        res.send('Agent deleted successfully');
    } catch (err) {
        console.error('Delete agent error:', err);
        res.status(500).send('Server error');
    }
});

// ==================== PROPERTY APPROVAL SHORTCUTS ====================
newapp2.post('/properties/approve/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM sales_approval WHERE id = ?', [id]);
        if (results.length === 0) return res.status(404).send('Property not found');
        const p = results[0];
        await db.query(
            `INSERT INTO all_properties (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description, sqft, image_data, video, amount, title, rentSell, \`property-type\`, agentId, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [p.ownerName, p.ownerEmail, p.ownerPhone, p.propertyAddress,
             p.bedrooms, p.bathrooms, p.description, p.sqft,
             p.image_data, p.video, p.amount, p.title,
             p.rentSell, p.property_type, p.agentId, 'approved']
        );
        await db.query('DELETE FROM sales_approval WHERE id = ?', [id]);
        res.send('Property approved');
    } catch (err) {
        console.error('Property approve shortcut error:', err);
        res.status(500).send('Error');
    }
});

newapp2.post('/properties/sell/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM all_properties WHERE id = ?', [id]);
        if (results.length === 0) return res.status(404).send('Property not found');
        const p = results[0];
        await db.query(
            `INSERT INTO sold_properties (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description, sqft, image_data, video, amount, title, rentSell, \`property-type\`, agentId, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [p.ownerName, p.ownerEmail, p.ownerPhone, p.propertyAddress,
             p.bedrooms, p.bathrooms, p.description, p.sqft,
             p.image_data, p.video, p.amount, p.title,
             p.rentSell, p['property-type'], p.agentId, 'sold']
        );
        await db.query('DELETE FROM all_properties WHERE id = ?', [id]);
        res.send('Property marked as sold');
    } catch (err) {
        console.error('Property sell shortcut error:', err);
        res.status(500).send('Error');
    }
});

// ==================== AGENT DASHBOARD ====================
newapp2.get('/submit-listing', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    if (!agentId) return res.status(400).send('Invalid session: Agent ID not found');

    try {
        const [
            [totalPropsRows],
            [totalAgentsRows],
            [pendingRows],
            [soldRows],
            [activities],
            [agents],
            [approvals],
            [customers],
            [soldProps],
            [settings]
        ] = await Promise.all([
            db.query(`SELECT COUNT(*) AS totalProperties FROM (SELECT id FROM all_properties WHERE agentId = ? UNION SELECT id FROM sold_properties WHERE agentId = ?) AS combined`, [agentId, agentId]),
            db.query(`SELECT COUNT(*) AS totalAgents FROM signin WHERE role = 'agent'`),
            db.query(`SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`, [agentId]),
            db.query(`SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`, [agentId]),
            db.query(`SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`, [agentId]),
            db.query(`SELECT id, firstName, lastName, email, phone FROM signin WHERE id = ?`, [agentId]),
            db.query(`SELECT s.id, s.title, s.status, u.firstName AS agentName FROM sales_approval s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ? AND s.status = 'pending'`, [agentId]),
            db.query(`SELECT firstName, lastName, email, phone, role FROM signin WHERE role = 'user' LIMIT 10`),
            db.query(`SELECT s.title, u.firstName AS agentName, s.amount, s.created_at AS soldDate FROM sold_properties s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ?`, [agentId]),
            db.query(`SELECT 'G.O Aregban Real Estate' AS siteTitle, ? AS adminEmail`, [ADMIN_EMAIL])
        ]);

        res.render('agent-dashboard', {
            totalProperties: totalPropsRows[0].totalProperties,
            totalAgents: totalAgentsRows[0].totalAgents,
            pendingApprovals: pendingRows[0].pendingApprovals,
            soldProperties: soldRows[0].soldProperties,
            activities, agents, approvals, customers, soldProps,
            siteTitle: settings[0].siteTitle,
            adminEmail: settings[0].adminEmail,
            username: req.user.firstName,
            surname: req.user.lastName,
            isAdmin: req.session.role === 'admin',
            isAgent: req.session.role === 'agent'
        });
    } catch (err) {
        console.error('Submit listing error:', err);
        res.status(500).send('Server error');
    }
});

newapp2.get('/manage-listings', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    if (!agentId) return res.status(400).send('Invalid session: Agent ID not found');

    try {
        const [
            [pendingListings],
            [approvedListings],
            [soldListings],
            [allListings]
        ] = await Promise.all([
            db.query(`SELECT id, title, status FROM sales_approval WHERE agentId = ? AND status = 'pending'`, [agentId]),
            db.query(`SELECT id, title, status FROM all_properties WHERE agentId = ? AND status = 'approved'`, [agentId]),
            db.query(`SELECT id, title, status FROM sold_properties WHERE agentId = ?`, [agentId]),
            db.query(`(SELECT id, title, status FROM all_properties WHERE agentId = ?) UNION (SELECT id, title, status FROM sold_properties WHERE agentId = ?)`, [agentId, agentId])
        ]);

        res.render('manage-listing', {
            title: 'Manage Listings',
            pendingListings, approvedListings, soldListings, allListings
        });
    } catch (err) {
        console.error('Manage listings error:', err);
        res.status(500).send('Server error');
    }
});

newapp2.get('/agent/listings/all', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    try {
        const [results] = await db.query('SELECT id, title, status FROM all_properties WHERE agentId = ?', [agentId]);
        res.json(results);
    } catch (err) {
        console.error('Agent listings all error:', err);
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

newapp2.get('/agent/listings/pending', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    try {
        const [results] = await db.query('SELECT id, title, status FROM sales_approval WHERE agentId = ? AND status = "pending"', [agentId]);
        res.json(results);
    } catch (err) {
        console.error('Agent listings pending error:', err);
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

newapp2.get('/agent/listings/approved', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    try {
        const [results] = await db.query('SELECT id, title, status FROM all_properties WHERE agentId = ? AND status = "approved"', [agentId]);
        res.json(results);
    } catch (err) {
        console.error('Agent listings approved error:', err);
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

newapp2.get('/agent/listings/sold', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    try {
        const [results] = await db.query('SELECT id, title, status FROM sold_properties WHERE agentId = ?', [agentId]);
        res.json(results);
    } catch (err) {
        console.error('Agent listings sold error:', err);
        res.status(500).json({ error: 'Database error: ' + err.message });
    }
});

newapp2.get('/edit-property/:id', requireAgent, async (req, res) => {
    const propertyId = req.params.id;
    const agentId = req.session.userId;

    try {
        const [[pending], [approved], [sold]] = await Promise.all([
            db.query(`SELECT *, 'pending' AS tableName FROM sales_approval WHERE id = ? AND agentId = ?`, [propertyId, agentId]),
            db.query(`SELECT *, 'approved' AS tableName FROM all_properties WHERE id = ? AND agentId = ?`, [propertyId, agentId]),
            db.query(`SELECT *, 'sold' AS tableName FROM sold_properties WHERE id = ? AND agentId = ?`, [propertyId, agentId])
        ]);

        const property = [...pending, ...approved, ...sold][0];
        if (!property) return res.status(404).json({ error: 'Property not found or not owned by you' });
        res.json(property);
    } catch (err) {
        console.error('Edit property fetch error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

newapp2.post('/update-property/:id', requireAgent, async (req, res) => {
    const propertyId = req.params.id;
    const agentId = req.session.userId;
    const { title, description, amount, rentSell, property_type, status, bedrooms, bathrooms } = req.body;

    try {
        const [findResults] = await db.query(`
            SELECT 'pending' AS tableName FROM sales_approval WHERE id = ? AND agentId = ?
            UNION
            SELECT 'approved' AS tableName FROM all_properties WHERE id = ? AND agentId = ?
            UNION
            SELECT 'sold' AS tableName FROM sold_properties WHERE id = ? AND agentId = ?
        `, [propertyId, agentId, propertyId, agentId, propertyId, agentId]);

        if (findResults.length === 0) return res.status(404).json({ error: 'Property not found or not owned by you' });

        const tableName = findResults[0].tableName;
        let table, propertyTypeColumn;
        if (tableName === 'pending') { table = 'sales_approval'; propertyTypeColumn = 'property_type'; }
        else if (tableName === 'approved') { table = 'all_properties'; propertyTypeColumn = '`property-type`'; }
        else { table = 'sold_properties'; propertyTypeColumn = '`property-type`'; }

        await db.query(
            `UPDATE ${table} SET title = ?, description = ?, amount = ?, rentSell = ?, ${propertyTypeColumn} = ?, status = ?, bedrooms = ?, bathrooms = ? WHERE id = ? AND agentId = ?`,
            [title, description, amount, rentSell, property_type, status, bedrooms, bathrooms, propertyId, agentId]
        );
        res.json({ success: true, message: 'Property updated successfully' });
    } catch (err) {
        console.error('Update property error:', err);
        res.status(500).json({ error: 'Update failed: ' + err.message });
    }
});

// ==================== TRACK PERFORMANCE ====================
newapp2.get('/track-performance', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    const chartData = {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        views: [1200, 1500, 1800, 2200, 2500, 2800],
        inquiries: [100, 150, 200, 250, 300, 350]
    };

    try {
        const [
            [totalPropsRows],
            [pendingRows],
            [soldRows],
            [activities]
        ] = await Promise.all([
            db.query(`SELECT COUNT(*) AS totalProperties FROM (SELECT id FROM all_properties WHERE agentId = ? UNION SELECT id FROM sold_properties WHERE agentId = ?) AS combined`, [agentId, agentId]),
            db.query(`SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`, [agentId]),
            db.query(`SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`, [agentId]),
            db.query(`SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`, [agentId])
        ]);

        res.render('track-performance', {
            title: 'Track Performance',
            totalProperties: totalPropsRows[0].totalProperties,
            pendingApprovals: pendingRows[0].pendingApprovals,
            soldProperties: soldRows[0].soldProperties,
            activities,
            chartData
        });
    } catch (err) {
        console.error('Track performance error:', err);
        res.status(500).send('Server error');
    }
});

// ==================== CHAT ====================
newapp2.get('/chat', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const successMessage = req.query.success;
    const receiverId = req.query.receiverId;

    try {
        if (receiverId) {
            const [receiverResults] = await db.query('SELECT firstName, lastName, role FROM signin WHERE id = ?', [receiverId]);
            let receiverName = 'Unknown';
            let isAgent = false;
            if (receiverResults.length > 0) {
                const r = receiverResults[0];
                receiverName = `${r.firstName || ''} ${r.lastName || ''}`.trim() || (r.role === 'admin' ? 'Admin' : 'Unknown');
                isAgent = r.role === 'agent';
            }
            const [messages] = await db.query(
                'SELECT * FROM chat_messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC',
                [userId, receiverId, receiverId, userId]
            );
            res.render('chat', { messages, userId, receiverId, success: successMessage, receiverName, isAgent, chatList: null });
        } else {
            const [chatList] = await db.query(`
                SELECT DISTINCT 
                    CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AS receiverId,
                    s.firstName, s.lastName, s.role,
                    (SELECT message FROM chat_messages 
                     WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) 
                        OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) 
                     ORDER BY timestamp DESC LIMIT 1) AS lastMessage,
                    (SELECT timestamp FROM chat_messages 
                     WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) 
                        OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) 
                     ORDER BY timestamp DESC LIMIT 1) AS lastMessageTime
                FROM chat_messages cm
                JOIN signin s ON s.id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END
                WHERE cm.sender_id = ? OR cm.receiver_id = ?
                ORDER BY lastMessageTime DESC`,
                [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId]
            );
            const processedChatList = chatList.map(chat => ({
                receiverId: chat.receiverId,
                receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || (chat.role === 'admin' ? 'Admin' : 'Unknown'),
                isAgent: chat.role === 'agent',
                lastMessage: chat.lastMessage,
                lastMessageTime: chat.lastMessageTime
            }));
            res.render('chat', { messages: null, userId, receiverId: null, success: successMessage, receiverName: null, isAgent: null, chatList: processedChatList });
        }
    } catch (err) {
        console.error('Chat error:', err);
        res.status(500).send('Error loading chat');
    }
});

newapp2.get('/customer-chat', ensureAuthenticated, async (req, res) => {
    const clientId = req.user.id;
    try {
        const [agents] = await db.query("SELECT id FROM signin WHERE role = 'agent' LIMIT 1");
        if (agents.length === 0) return res.send('No agents available at this time.');
        const agentId = agents[0].id;
        res.render('customer-chat', { agentId, clientId });
    } catch (err) {
        console.error('Customer chat error:', err);
        res.status(500).send('Server error');
    }
});

newapp2.get('/api/staff-list', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, firstName, lastName, role FROM signin WHERE role IN ('admin', 'agent')");
        res.json(results);
    } catch (err) {
        console.error('Staff list error:', err);
        res.status(500).json([]);
    }
});

newapp2.post('/chat/send', ensureAuthenticated, async (req, res) => {
    const { senderId, receiverId, message } = req.body;
    if (!senderId || !receiverId || !message) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    try {
        const [result] = await db.query(
            'INSERT INTO chat_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())',
            [senderId, receiverId, message]
        );
        res.json({ success: true, messageId: result.insertId });
    } catch (err) {
        console.error('Chat send error:', err);
        res.status(500).json({ error: 'Error saving message' });
    }
});

newapp2.get('/agent-chat', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const receiverId = req.query.receiverId;

    try {
        if (receiverId) {
            const [receiverResults] = await db.query('SELECT firstName, lastName, role FROM signin WHERE id = ?', [receiverId]);
            let receiverName = 'Client';
            let isClient = false;
            if (receiverResults.length > 0) {
                const r = receiverResults[0];
                receiverName = `${r.firstName || ''} ${r.lastName || ''}`.trim() || 'Client';
                isClient = r.role === 'user';
            }
            const [messages] = await db.query(
                'SELECT * FROM chat_messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC',
                [userId, receiverId, receiverId, userId]
            );
            res.render('agent-chat', { messages, userId, receiverId, receiverName, isClient, chatList: null });
        } else {
            const [chatList] = await db.query(`
                SELECT DISTINCT 
                    CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AS receiverId,
                    s.firstName, s.lastName, s.role,
                    (SELECT message FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessage,
                    (SELECT timestamp FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessageTime
                FROM chat_messages cm
                JOIN signin s ON s.id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END
                WHERE cm.receiver_id = ?
                ORDER BY lastMessageTime DESC`,
                [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId]
            );
            const processedChatList = chatList.map(chat => ({
                receiverId: chat.receiverId,
                receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || 'Client',
                isClient: chat.role === 'user',
                lastMessage: chat.lastMessage,
                lastMessageTime: chat.lastMessageTime
            }));
            res.render('agent-chat', { messages: null, userId, receiverId: null, receiverName: null, isClient: null, chatList: processedChatList });
        }
    } catch (err) {
        console.error('Agent chat error:', err);
        res.status(500).send('Error loading chats');
    }
});

newapp2.post('/agent-chat/send', ensureAuthenticated, async (req, res) => {
    const { senderId, receiverId, message } = req.body;
    if (!senderId || !receiverId || !message) return res.status(400).json({ error: 'Missing required fields' });
    try {
        const [result] = await db.query(
            'INSERT INTO chat_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())',
            [senderId, receiverId, message]
        );
        res.json({ success: true, messageId: result.insertId });
    } catch (err) {
        console.error('Agent chat send error:', err);
        res.status(500).json({ error: 'Error saving message' });
    }
});

newapp2.get('/admin-chat', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const receiverId = req.query.receiverId;

    try {
        if (receiverId) {
            const [receiverResults] = await db.query('SELECT firstName, lastName, role FROM signin WHERE id = ?', [receiverId]);
            let receiverName = 'Client';
            let isClient = false;
            if (receiverResults.length > 0) {
                const r = receiverResults[0];
                receiverName = `${r.firstName || ''} ${r.lastName || ''}`.trim() || 'Client';
                isClient = r.role === 'user';
            }
            const [messages] = await db.query(
                'SELECT * FROM chat_messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC',
                [userId, receiverId, receiverId, userId]
            );
            res.render('admin-chat', { messages, userId, receiverId, receiverName, isClient, chatList: null });
        } else {
            const [chatList] = await db.query(`
                SELECT DISTINCT 
                    CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AS receiverId,
                    s.firstName, s.lastName, s.role,
                    (SELECT message FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessage,
                    (SELECT timestamp FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessageTime
                FROM chat_messages cm
                JOIN signin s ON s.id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END
                WHERE cm.receiver_id = ?
                ORDER BY lastMessageTime DESC`,
                [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId]
            );
            const processedChatList = chatList.map(chat => ({
                receiverId: chat.receiverId,
                receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || 'Client',
                isClient: chat.role === 'user',
                lastMessage: chat.lastMessage,
                lastMessageTime: chat.lastMessageTime
            }));
            res.render('admin-chat', { messages: null, userId, receiverId: null, receiverName: null, isClient: null, chatList: processedChatList });
        }
    } catch (err) {
        console.error('Admin chat error:', err);
        res.status(500).send('Error loading chats');
    }
});

// ==================== MISC ROUTES ====================
newapp2.get('/inquiries', ensureAuthenticated, async (req, res) => {
    if (req.session.role !== 'agent' && req.user.email !== ADMIN_EMAIL) {
        return res.redirect('/login');
    }
    try {
        const [enquiries] = await db.query('SELECT * FROM enquiries ORDER BY timestamp DESC');
        res.render('enquiry', { enquiries });
    } catch (err) {
        console.error('Inquiries error:', err);
        res.status(500).send('Server error');
    }
});

newapp2.get('/property-valuation', ensureAuthenticated, (req, res) => {
    res.render('property-valuation');
});

newapp2.post('/valuate', ensureAuthenticated, async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: 'Prompt is required' });

    try {
        const completion = await groq.chat.completions.create({
            model: 'llama-3.1-8b-instant',
            messages: [
                { role: 'system', content: 'You are a Nigerian real estate valuation expert. Respond with valid JSON only.' },
                { role: 'user', content: prompt }
            ],
            max_tokens: 1000,
            temperature: 0.3
        });

        const raw = completion.choices[0].message.content;
        const match = raw.match(/\{[\s\S]*\}/);
        if (!match) throw new Error('Could not parse AI response');
        res.json(JSON.parse(match[0]));
    } catch (error) {
        console.error('Groq valuation error:', error.message);
        res.status(500).json({ error: 'Valuation failed: ' + error.message });
    }
});

newapp2.get('/gallery', async (req, res) => {
    try {
        const [card] = await db.query('SELECT * FROM all_properties ORDER BY id DESC');
        res.render('gallery', { card });
    } catch (err) {
        console.error('Gallery error:', err);
        res.status(500).send('Server error');
    }
});

// ==================== 404 HANDLER ====================
newapp2.use((req, res) => {
    res.status(404).send('Page not found');
});

// ==================== GLOBAL ERROR HANDLER ====================
newapp2.use((err, req, res, next) => {
    console.error('Unhandled error:', err.stack);
    res.status(500).send('Something went wrong. Please try again later.');
});

// ==================== START SERVER ====================
server.listen(10000, () => {
    console.log('🏠 G.O Aregban Real Estate server running on port 10000');
});
