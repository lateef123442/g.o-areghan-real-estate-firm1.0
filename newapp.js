// Step 1: Node modules export
const fs = require('fs');
const path = require('path');
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const cors = require('cors');
const passport = require('passport');
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

const newapp2 = express();
const server = http.createServer(newapp2);
const io = socketIo(server);

newapp2.use(cors());
newapp2.use(express.json());
newapp2.use(express.urlencoded({ extended: true }));

// ==================== ADMIN EMAILS ====================
const ADMIN_EMAILS = ['esvgoddey@gmail.com', 'ibarealestate2023@gmail.com'];

function isAdminEmail(email) {
    return ADMIN_EMAILS.includes(email);
}

// ==================== IMAGE PATH HELPER ====================
// Multer saves paths as "uploads/images/xxx.jpg" (no leading slash).
// The static route serves them at "/uploads/...".
// This normalises stored paths so <img src="..."> always works.
function normalizeImagePaths(paths) {
    if (!paths) return '';
    return paths.split(',')
        .map(p => {
            p = p.trim();
            if (!p) return '';
            // Already an absolute URL or data URI — leave alone
            if (p.startsWith('http') || p.startsWith('data:')) return p;
            // Add leading slash if missing
            return p.startsWith('/') ? p : '/' + p;
        })
        .filter(Boolean)
        .join(',');
}

// ==================== MULTER CONFIG ====================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let dir = 'uploads/';
        if (file.fieldname === 'image')          dir = 'uploads/images/';
        else if (file.fieldname === 'video')     dir = 'uploads/videos/';
        else if (file.fieldname === 'documents') dir = 'uploads/documents/';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
        cb(null, Date.now() + '_' + safeName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedMimeTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp',
        'video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo', 'video/webm',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'text/plain',
    ];
    if (allowedMimeTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error(`File type not allowed: ${file.mimetype}`), false);
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 20 * 1024 * 1024 }
});

// ==================== SESSION ====================
newapp2.use(session({
    secret: process.env.SESSION_SECRET || 'lateef.2008',
    resave: false,
    saveUninitialized: false
}));

// ==================== AUTH MIDDLEWARE ====================
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

function requireAgent(req, res, next) {
    if (req.session && req.session.role === 'agent' && req.session.userId) {
        next();
    } else {
        console.log('Unauthorized access attempt:', req.session);
        res.status(401).json({ error: 'Unauthorized: Please log in as an agent' });
    }
}

// ==================== PASSPORT ====================
newapp2.use(passport.initialize());
newapp2.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
    try {
        const [results] = await db.query('SELECT * FROM signin WHERE id = ?', [id]);
        done(null, results[0] || false);
    } catch (err) {
        done(err);
    }
});

// ==================== NODEMAILER ====================
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'esvgoddey@gmail.com',
        pass: process.env.EMAIL_PASS || 'gwps gwod slos pjsl'
    }
});

// ==================== DATABASE POOL ====================
const db = mysql.createPool({
    host: '127.0.0.1',
    database: 'u166499615_realestate',
    user: 'u166499615_ahmed',
    password: 'Lateef.2008',
    port: 3306,
});

async function connectWithRetry(retries = 5, delayMs = 3000) {
    for (let i = 1; i <= retries; i++) {
        try {
            await db.query('SELECT 1');
            console.log('✅ Database Connected!');
            return;
        } catch (err) {
            console.error(`❌ DB connection attempt ${i}/${retries} failed: ${err.message}`);
            if (i < retries) {
                console.log(`   Retrying in ${delayMs / 1000}s...`);
                await new Promise(res => setTimeout(res, delayMs));
            } else {
                console.error('   All DB connection attempts failed. Server will continue but DB calls may fail.');
            }
        }
    }
}

// ==================== STATIC FILES ====================
newapp2.set('views', path.join(__dirname, 'views'));
newapp2.use('/img',      express.static(path.join(__dirname, 'public', 'img')));
newapp2.use('/css',      express.static(path.join(__dirname, 'public', 'css')));
newapp2.use('/plugins',  express.static(path.join(__dirname, 'public', 'plugins')));
newapp2.use('/dist',     express.static(path.join(__dirname, 'public', 'dist')));
newapp2.use('/js',       express.static(path.join(__dirname, 'public', 'js')));
newapp2.use('/data',     express.static(path.join(__dirname, 'public', 'data')));
newapp2.use('/uploads',  express.static(path.join(__dirname, 'uploads')));

newapp2.set('view engine', 'ejs');

// ==================== BODY PARSER ====================
newapp2.use(bodyParser.json({ limit: '50mb' }));
newapp2.use(bodyParser.urlencoded({ limit: '50mb', extended: true, parameterLimit: 1000000 }));
newapp2.use(cookieParser());

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
    socket.on('joinChat', (userId) => {
        socket.join(String(userId));
        console.log(`User ${userId} joined their room`);
    });

    socket.on('sendMessage', async ({ senderId, receiverId, message }) => {
        try {
            await db.query(
                'INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
                [senderId, receiverId, message]
            );
            const timestamp = new Date();
            socket.emit('messageSent', { message, timestamp });
            io.to(String(receiverId)).emit('receiveMessage', { message, senderId, timestamp });
        } catch (err) {
            console.error('DB error in sendMessage:', err);
            socket.emit('messageError', { error: 'Failed to send message' });
        }
    });
});

// ==================== API ROUTES ====================
newapp2.get('/api/check-login', (req, res) => {
    if (req.user) res.json({ loggedIn: true, username: req.user.firstName });
    else res.json({ loggedIn: false });
});

// ==================== PUBLIC PAGES ====================
newapp2.get('/', async (req, res) => {
    try {
        const [card] = await db.query("SELECT * FROM all_properties LIMIT 3");
        res.render('website', { card });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/website', async (req, res) => {
    try {
        const [card] = await db.query("SELECT * FROM all_properties LIMIT 3");
        res.render('website', { card });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/login', (req, res) => res.render('login'));
newapp2.get('/forgot-password.html', (req, res) => res.render('forgotten-password'));

// ==================== REGISTRATION ====================
newapp2.post('/submit', async (req, res) => {
    const { firstName, middleName, lastName, email, phone, confirmPassword } = req.body;

    if (!validator.isEmail(email)) {
        return res.status(400).render('invalid-email', { error: 'Please provide a valid email address' });
    }

    try {
        const [existing] = await db.query('SELECT COUNT(*) AS count FROM signin WHERE email = ?', [email]);
        if (existing[0].count > 0) return res.render('invalid-email', { error: 'This email is already registered' });

        const hashedPassword = bcrypt.hashSync(confirmPassword, 10);
        await db.query(
            'INSERT INTO signin (firstName, middleName, lastName, email, phone, confirmPassword, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [firstName, middleName, lastName, email, phone, hashedPassword, 'user']
        );

        const mailOptions = {
            from: process.env.EMAIL_USER || 'esvgoddey@gmail.com',
            to: email,
            subject: 'Welcome to G.O AREGHAN Real Estate Firm & Consultant',
            html: `
                <h1>Welcome to G.O AREGHAN Real Estate Firm & Consultant!</h1>
                <p>Dear ${firstName} ${lastName},</p>
                <p>Thank you for creating an account with G.O AREGHAN Real Estate Firm & Consultant. We're excited to help you find your dream property!</p>
                <p>Best regards,<br>The G.O AREGHAN Real Estate Firm & Consultant Team</p>
            `
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) console.error('Error sending welcome email:', error);
            else console.log('Welcome email sent:', info.response);
        });

        return res.render('valid-email');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

newapp2.get('/invalid-reg-details', (req, res) => res.render('signin-page'));
newapp2.get('/valid-reg-details',   (req, res) => res.render('login'));
newapp2.get('/already-have-acct',   (req, res) => res.render('login'));

// ==================== LOGIN ====================
newapp2.post('/dashboard', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [results] = await db.query('SELECT * FROM signin WHERE email = ?', [email]);

        if (results.length === 0 || !bcrypt.compareSync(password, results[0].confirmPassword)) {
            return res.render('invalid-login');
        }

        const user = results[0];

        req.login(user, async (err) => {
            if (err) { console.error(err); return res.status(500).send('Login error'); }

            if (isAdminEmail(email)) {
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
                        db.query(`SELECT COUNT(*) AS totalProperties FROM (
                            SELECT id FROM all_properties WHERE agentId = ?
                            UNION SELECT id FROM sold_properties WHERE agentId = ?
                            UNION SELECT id FROM sales_approval WHERE agentId = ?
                        ) AS combined`, [agentId, agentId, agentId]),
                        db.query(`SELECT COUNT(*) AS totalAgents FROM signin WHERE role = 'agent'`),
                        db.query(`SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`, [agentId]),
                        db.query(`SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`, [agentId]),
                        db.query(`SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`, [agentId]),
                        db.query(`SELECT id, firstName, lastName, email, phone FROM signin WHERE id = ?`, [agentId]),
                        db.query(`SELECT s.id, s.title, s.status, u.firstName AS agentName FROM sales_approval s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ? AND s.status = 'pending'`, [agentId]),
                        db.query(`SELECT firstName, lastName, email, phone, role FROM signin WHERE role = 'user' LIMIT 10`),
                        db.query(`SELECT s.title, u.firstName AS agentName, s.amount, s.created_at AS soldDate FROM sold_properties s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ?`, [agentId]),
                        db.query(`SELECT 'G.O AREGHAN Real Estate Firm & Consultant' AS siteTitle, 'esvgoddey@gmail.com' AS adminEmail`)
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
                    console.error('Agent data fetch error:', dataErr);
                    return res.status(500).send('Server error');
                }
            }

            req.session.isAdmin = false;
            req.session.isAgent = false;
            try {
                const [card] = await db.query("SELECT * FROM all_properties LIMIT 3");
                return res.render('website', { card });
            } catch (cardErr) {
                console.error(cardErr.message);
                return res.status(500).send('Server error');
            }
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ==================== NAVIGATION ROUTES ====================
newapp2.get('/valid-login', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized: Please log in first.');
    res.redirect('/track-sales.html');
});

newapp2.get('/invalid-login', (req, res) => res.render('login'));

newapp2.get('/index.html', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties");
        res.render('index', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/buy-page.html', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties WHERE rentSell = 'sell'");
        res.render('buy-page', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/home-improvemet-page.html', ensureAuthenticated, (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    res.render('home-improvemet-page', { isAdmin: isAdminEmail(req.user.email) });
});

newapp2.get('/sell-page.html', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties");
        res.render('sell-page', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/rent-page.html', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties WHERE rentSell = 'rent'");
        res.render('rent-page', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/message-page.html', ensureAuthenticated, (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    res.render('message-page', { isAdmin: isAdminEmail(req.user.email) });
});

newapp2.get('/setting-page.html', ensureAuthenticated, (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    res.render('setting-page', { isAdmin: isAdminEmail(req.user.email) });
});

newapp2.get('/sales-approval.html', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM sales_approval");
        res.render('sales-approval', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/notificatin-page.html', ensureAuthenticated, (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    res.render('notification-page', { isAdmin: isAdminEmail(req.user.email) });
});

newapp2.get('/tour-requested.html', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [results] = await db.query('SELECT *, (SELECT COUNT(*) FROM request_tour) AS count FROM request_tour');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('requested-tour', { card: results, rowCount, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Database query error.'); }
});

newapp2.get('/profile-page.html', ensureAuthenticated, async (req, res) => {
    if (!req.user || !req.user.id) return res.redirect('/login');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [results] = await db.query(
            'SELECT id, firstName, middleName, lastName, email, phone FROM signin WHERE id = ?',
            [req.user.id]
        );
        if (results.length === 0) return res.status(404).send('User not found');
        const u = results[0];
        res.render('profile-page', { id: u.id, firstName: u.firstName, middleName: u.middleName, lastName: u.lastName, email: u.email, phone: u.phone, isAdmin });
    } catch (err) { console.error(err); res.status(500).send('Internal Server Error'); }
});

// ==================== TRACK SALES ====================
newapp2.get('/track-sales.html', ensureAuthenticated, async (req, res) => {
    try {
        const [
            [pendingSalesRows],
            [allSalesRows],
            [soldPropsRows],
            [customersRows],
            [soldThisMonthRows],
            [propertyTypesRows],
            [monthlySoldRows]
        ] = await Promise.all([
            db.query("SELECT COUNT(*) as count FROM sales_approval"),
            db.query("SELECT COUNT(*) as count FROM all_properties"),
            db.query("SELECT COUNT(*) as count FROM sold_properties"),
            db.query("SELECT COUNT(DISTINCT email) as count FROM signin"),
            db.query("SELECT COUNT(*) as count FROM sold_properties WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())"),
            db.query("SELECT `property-type` as type, COUNT(*) as count FROM all_properties WHERE `property-type` IN ('Plots of Land', 'Duplex', 'Bungalow', 'Storey Building', 'Self Contain', 'Flat', 'Apartment') GROUP BY `property-type`"),
            db.query(
                "SELECT DATE_FORMAT(created_at, '%b %Y') as month, COUNT(*) as count " +
                "FROM sold_properties WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH) " +
                "GROUP BY DATE_FORMAT(created_at, '%Y-%m') ORDER BY DATE_FORMAT(created_at, '%Y-%m') ASC"
            )
        ]);

        const stats = {
            pendingSales: pendingSalesRows[0].count || 0,
            allSales: allSalesRows[0].count || 0,
            soldProperties: soldPropsRows[0].count || 0,
            customers: customersRows[0].count || 0,
            soldThisMonth: soldThisMonthRows[0].count || 0,
            propertyTypes: propertyTypesRows,
            monthlySold: monthlySoldRows.map(row => ({ month: row.month, count: parseInt(row.count) || 0 }))
        };

        res.render('sales-tracker', { stats, isAdmin: true });
    } catch (err) {
        console.error('Track sales error:', err);
        res.status(500).send('Server error');
    }
});

// ==================== REGISTER PAGE ====================
newapp2.get('/register.html', (req, res) => res.render('signin-page'));

// ==================== PROPERTY UPLOAD ====================
// NEW fields: land_size, building_size, num_flats — all optional
// SQL required (run alter_tables.sql):
//   ALTER TABLE sales_approval ADD COLUMN IF NOT EXISTS land_size VARCHAR(100) NULL ...
//   ALTER TABLE all_properties  ADD COLUMN IF NOT EXISTS land_size VARCHAR(100) NULL ...
//   ALTER TABLE sold_properties ADD COLUMN IF NOT EXISTS land_size VARCHAR(100) NULL ...
newapp2.post('/upload', (req, res, next) => {
    upload.fields([
        { name: 'image',     maxCount: 10 },
        { name: 'video',     maxCount: 5  },
        { name: 'documents', maxCount: 10 }
    ])(req, res, (err) => {
        if (err) { console.error('Multer error:', err.message); return res.status(400).json({ success: false, message: err.message }); }
        next();
    });
}, async (req, res) => {
    if (!req.user) return res.status(401).json({ success: false, message: 'Unauthorized' });

    const userId = req.user.id;
    try {
        const [results] = await db.query('SELECT role FROM signin WHERE id = ?', [userId]);
        if (results.length === 0) return res.status(404).json({ success: false, message: 'User not found' });

        const files         = req.files || {};
        const imagePaths    = normalizeImagePaths(files.image     ? files.image.map(f => f.path).join(',')     : '');
        const videoPaths    = files.video     ? files.video.map(f => f.path).join(',')     : '';
        const documentPaths = files.documents ? files.documents.map(f => f.path).join(',') : '';

        const {
            ownerName, ownerEmail, ownerPhone, propertyAddress,
            bedrooms, bathrooms, sqft, description, title,
            rentSell, amount, property_type,
            // NEW fields
            land_size, building_size, num_flats
        } = req.body;

        await db.query(
            `INSERT INTO sales_approval
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft,
             land_size, building_size, num_flats,
             image_data, video, documents, description, title, rentSell, amount, property_type, agentId)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                ownerName    || null,
                ownerEmail   || null,
                ownerPhone   || null,
                propertyAddress || null,
                bedrooms     || null,
                bathrooms    || null,
                sqft         || null,
                land_size    || null,
                building_size || null,
                num_flats    ? parseInt(num_flats) : null,
                imagePaths, videoPaths, documentPaths,
                description  || null,
                title        || null,
                rentSell     || null,
                amount       || null,
                property_type || null,
                userId
            ]
        );

        const notifyAdmins = ADMIN_EMAILS.map(adminEmail => {
            const mailOptions = {
                from: process.env.EMAIL_USER || 'esvgoddey@gmail.com',
                to: adminEmail,
                subject: 'New Property Listing Submitted for Approval',
                html: `
                    <h2>New Property Listing Submitted</h2>
                    <p><strong>Title:</strong> ${title || 'N/A'}</p>
                    <p><strong>Agent ID:</strong> ${userId}</p>
                    <p><strong>Address:</strong> ${propertyAddress || 'N/A'}</p>
                    <p><strong>Amount:</strong> ₦${amount || 'N/A'}</p>
                    <p><strong>Type:</strong> ${property_type || 'N/A'}</p>
                    <p><strong>Land Size:</strong> ${land_size || 'N/A'}</p>
                    <p><strong>Building Size:</strong> ${building_size || 'N/A'}</p>
                    <p><strong>No. of Flats:</strong> ${num_flats || 'N/A'}</p>
                    <p>Please log in to review and approve/decline this listing.</p>
                `
            };
            return transporter.sendMail(mailOptions);
        });
        Promise.all(notifyAdmins).catch(e => console.error('Admin notification email error:', e));

        res.json({ success: true, message: 'Property uploaded successfully! Your listing has been submitted for review.' });
    } catch (err) {
        console.error('Error in /upload:', err);
        res.status(500).json({ success: false, message: 'Error uploading property: ' + err.message });
    }
});

// ==================== SALES ROUTES ====================
newapp2.get('/sales-completed', async (req, res) => {
    if (!req.user) return res.redirect('/login');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties");
        res.render('sell-page', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/sales-approved', ensureAuthenticated, (req, res) => res.redirect('/sales-approval.html'));
newapp2.get('/sales-declined', ensureAuthenticated, (req, res) => res.redirect('/sales-approval.html'));

// ==================== REQUEST TOUR ====================
newapp2.get('/request-tour', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties WHERE id = ?", [propertyId]);
        if (card.length === 0) return res.status(404).send('No property found with that ID.');
        res.render('request-tour', { property: card[0], isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/view', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const propertyId = req.query.id;
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM sales_approval WHERE id = ?", [propertyId]);
        if (card.length === 0) return res.status(404).send('No property found with that ID.');
        res.render('request-tour', { property: card[0], isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.post('/submit-tour', async (req, res) => {
    const { name, email, phone, date, time } = req.body;
    try {
        await db.query('INSERT INTO request_tour (name, email, phone, date, time) VALUES (?, ?, ?, ?, ?)', [name, email, phone, date, time]);
        res.render('tour-submitted');
    } catch (err) { res.status(500).send('Error inserting data: ' + err); }
});

newapp2.get('/tour-submitted', ensureAuthenticated, async (req, res) => {
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [card] = await db.query("SELECT * FROM all_properties");
        res.render('index', { card, isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.post('/improvement-request-form', async (req, res) => {
    const { name, email, phone, message } = req.body;
    try {
        await db.query('INSERT INTO homeImprovement (name, email, phone, message) VALUES (?, ?, ?, ?)', [name, email, phone, message]);
        res.render('tour-submitted');
    } catch (err) { res.status(500).send('Error inserting data: ' + err); }
});

// ==================== PROFILE ====================
newapp2.get('/edit-profile', ensureAuthenticated, async (req, res) => {
    res.render('setting-page', { isAdmin: isAdminEmail(req.user.email) });
});

newapp2.post('/update-profile', ensureAuthenticated, async (req, res) => {
    const { firstName, middleName, lastName, email, phone, currentPassword } = req.body;
    const userId = req.user.id;
    try {
        const [results] = await db.query('SELECT confirmPassword FROM signin WHERE id = ?', [userId]);
        if (results.length === 0) return res.status(404).send('User not found');
        if (!bcrypt.compareSync(currentPassword, results[0].confirmPassword)) return res.status(401).send('Current password is incorrect');
        await db.query(
            'UPDATE signin SET firstName = ?, middleName = ?, lastName = ?, email = ?, phone = ? WHERE id = ?',
            [firstName, middleName, lastName, email, phone, userId]
        );
        res.redirect('/profile-page.html');
    } catch (err) { console.error(err); res.status(500).send('Error updating profile'); }
});

// ==================== MESSAGING ====================
newapp2.post('/message', ensureAuthenticated, async (req, res) => {
    const message = req.body.message;
    if (!message || typeof message !== 'string') return res.status(400).json({ error: 'Invalid message format' });
    const userId = req.user.id;
    try {
        const [results] = await db.query('SELECT firstName, email FROM signin WHERE id = ?', [userId]);
        if (results.length === 0) return res.status(404).json({ error: 'User not found' });
        const user = results[0];
        const mailOptions = {
            from: user.email,
            to: ADMIN_EMAILS.join(','),
            subject: `New Message from ${user.firstName}`,
            text: message,
            html: `<p><strong>From:</strong> ${user.firstName} (${user.email})</p><p>${message}</p>`
        };
        transporter.sendMail(mailOptions, (err) => {
            if (err) { console.error('Error sending email:', err); return res.status(500).json({ error: 'Failed to send message' }); }
            res.status(200).json({ success: true, message: 'Message sent successfully' });
        });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Internal server error' }); }
});

// ==================== SALES APPROVAL / DECLINE ====================
newapp2.get('/approve', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');

    try {
        const [results] = await db.query("SELECT * FROM sales_approval WHERE id = ?", [propertyId]);
        if (results.length === 0) return res.status(404).send('No property found with that ID.');

        const p = results[0];
        await db.query(
            `INSERT INTO all_properties
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft,
             land_size, building_size, num_flats,
             image_data, video, documents, description, title, rentSell, agentId, amount, \`property-type\`, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')`,
            [
                p.ownerName, p.ownerEmail, p.ownerPhone, p.propertyAddress,
                p.bedrooms, p.bathrooms, p.sqft,
                p.land_size || null, p.building_size || null, p.num_flats || null,
                normalizeImagePaths(p.image_data), p.video, p.documents || '',
                p.description, p.title, p.rentSell, p.agentId, p.amount, p.property_type
            ]
        );
        await db.query('INSERT INTO total_amount (amount) VALUES (?)', [p.amount]);
        await db.query('DELETE FROM sales_approval WHERE id = ?', [propertyId]);
        res.render('sales-approved-successfully');
    } catch (err) { console.error(err.message); res.status(500).send('Error processing approval: ' + err.message); }
});

newapp2.get('/decline', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');
    try {
        const [results] = await db.query("SELECT * FROM sales_approval WHERE id = ?", [propertyId]);
        if (results.length === 0) return res.status(404).send('No property found with that ID.');
        await db.query('DELETE FROM sales_approval WHERE id = ?', [propertyId]);
        res.render('sales-declined-successfully');
    } catch (err) { console.error(err.message); res.status(500).send('Error processing decline: ' + err.message); }
});

// ==================== CUSTOMERS ====================
newapp2.get('/view-customers.html', ensureAuthenticated, async (req, res) => {
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [results] = await db.query('SELECT id, firstName, middleName, email, phone, (SELECT COUNT(*) FROM signin) AS count FROM signin');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('customers', { customers: results, rowCount, isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) { console.error(err); res.status(500).send('Database query error.'); }
});

// ==================== TOUR APPROVAL ====================
newapp2.get('/approve-tour', ensureAuthenticated, async (req, res) => {
    const tourId = req.query.id;
    try {
        const [results] = await db.query('SELECT * FROM request_tour WHERE id = ?', [tourId]);
        if (results.length === 0) return res.status(404).send('Tour not found.');
        const tour = results[0];
        transporter.sendMail({
            from: process.env.EMAIL_USER || 'esvgoddey@gmail.com',
            to: tour.email,
            subject: 'Tour Request Approved',
            text: `Dear ${tour.name},\n\nYour tour request has been approved.\n\nBest regards,\nG.O AREGHAN Real Estate Firm & Consultant`
        }, async (error) => {
            if (error) { console.error(error); return res.status(500).send('Error sending email.'); }
            await db.query('DELETE FROM request_tour WHERE id = ?', [tourId]);
            res.render('tour-approved-successfully');
        });
    } catch (err) { console.error(err); res.status(500).send('Database query error.'); }
});

newapp2.get('/decline-tour', ensureAuthenticated, async (req, res) => {
    const tourId = req.query.id;
    try {
        const [results] = await db.query('SELECT * FROM request_tour WHERE id = ?', [tourId]);
        if (results.length === 0) return res.status(404).send('Tour not found.');
        const tour = results[0];
        transporter.sendMail({
            from: process.env.EMAIL_USER || 'esvgoddey@gmail.com',
            to: tour.email,
            subject: 'Tour Request Declined',
            text: `Dear ${tour.name},\n\nYour tour request has been declined.\n\nBest regards,\nG.O AREGHAN Real Estate Firm & Consultant`
        }, async (error) => {
            if (error) { console.error(error); return res.status(500).send('Error sending email.'); }
            await db.query('DELETE FROM request_tour WHERE id = ?', [tourId]);
            res.render('tour-declined-successfully');
        });
    } catch (err) { console.error(err); res.status(500).send('Database query error.'); }
});

newapp2.get('/tour-approved-successfully', ensureAuthenticated, async (req, res) => {
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [results] = await db.query('SELECT *, (SELECT COUNT(*) FROM request_tour) AS count FROM request_tour');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('requested-tour', { card: results, isAdmin, userId: req.user.id, userEmail: req.user.email, rowCount });
    } catch (err) { console.error(err.message); res.status(500).send('Database query error.'); }
});

newapp2.get('/tour-declined-successfully', ensureAuthenticated, async (req, res) => {
    const isAdmin = isAdminEmail(req.user.email);
    try {
        const [results] = await db.query('SELECT *, (SELECT COUNT(*) FROM request_tour) AS count FROM request_tour');
        const rowCount = results.length > 0 ? results[0].count : 0;
        res.render('requested-tour', { card: results, rowCount, isAdmin, userId: req.user.id, userEmail: req.user.email });
    } catch (err) { console.error(err.message); res.status(500).send('Database query error.'); }
});

// ==================== SEARCH ====================
newapp2.get('/search', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    const { location, min_price, max_price, min_beds, min_baths } = req.query;
    let sql = "SELECT * FROM all_properties WHERE 1=1";
    let values = [];
    if (location)   { sql += " AND propertyAddress LIKE ?"; values.push(`%${location}%`); }
    if (min_price)  { sql += " AND amount >= ?"; values.push(min_price); }
    if (max_price)  { sql += " AND amount <= ?"; values.push(max_price); }
    if (min_beds)   { sql += " AND bedrooms >= ?"; values.push(min_beds); }
    if (min_baths)  { sql += " AND bathrooms >= ?"; values.push(min_baths); }
    try {
        const [card] = await db.query(sql, values);
        res.render('index', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

newapp2.get('/buy-search-form', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const isAdmin = isAdminEmail(req.user.email);
    const { location, min_price, max_price, min_beds, min_baths } = req.query;
    let query = "SELECT * FROM all_properties WHERE rentSell = 'sell'";
    let queryParams = [];
    if (location && location.trim())     { query += " AND propertyAddress LIKE ?"; queryParams.push(`%${location}%`); }
    if (min_price && !isNaN(min_price))  { query += " AND amount >= ?"; queryParams.push(parseInt(min_price)); }
    if (max_price && !isNaN(max_price))  { query += " AND amount <= ?"; queryParams.push(parseInt(max_price)); }
    if (min_beds  && !isNaN(min_beds))   { query += " AND bedrooms >= ?"; queryParams.push(parseInt(min_beds)); }
    if (min_baths && !isNaN(min_baths))  { query += " AND bathrooms >= ?"; queryParams.push(parseInt(min_baths)); }
    try {
        const [card] = await db.query(query, queryParams);
        res.render('buy-page', { card, isAdmin });
    } catch (err) { console.error(err.message); res.status(500).send('Server error'); }
});

// ==================== CUSTOMER-FACING PAGES ====================
newapp2.get('/customer-buy-page.html', async (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'sell'";
    let params = [];
    if (req.query.property_type && req.query.property_type !== 'all') { query += " AND `property-type` = ?"; params.push(req.query.property_type); }
    try {
        const [card] = await db.query(query, params);
        res.render('customer-buy-page', { card });
    } catch (err) { console.error(err.message); res.status(500).send('Server error.'); }
});

newapp2.get('/costumer-sell-page.html', async (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'Rent'";
    let params = [];
    if (req.query.property_type && req.query.property_type !== 'all') { query += " AND `property-type` = ?"; params.push(req.query.property_type); }
    try {
        const [card] = await db.query(query, params);
        res.render('costumer-sell-page', { card });
    } catch (err) { console.error(err.message); res.status(500).send('Server error.'); }
});

newapp2.get('/customer-rent-page.html', async (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'Rent'";
    let params = [];
    if (req.query.property_type && req.query.property_type !== 'all') { query += " AND `property-type` = ?"; params.push(req.query.property_type); }
    try {
        const [card] = await db.query(query, params);
        res.render('customer-rent-page', { card });
    } catch (err) { console.error(err.message); res.status(500).send('Server error.'); }
});

// ==================== PROPERTY DETAIL ====================
newapp2.get('/property-detail', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId) return res.status(400).send('Property ID is required.');
    try {
        const [userResults] = await db.query("SELECT role FROM signin WHERE id = ?", [req.user.id]);
        if (userResults.length === 0) return res.status(404).send('User not found.');
        const isAdmin = isAdminEmail(req.user.email) || userResults[0].role === 'admin';
        let [propResults] = await db.query("SELECT * FROM all_properties WHERE id = ?", [propertyId]);
        if (propResults.length === 0) [propResults] = await db.query("SELECT * FROM sold_properties WHERE id = ?", [propertyId]);
        if (propResults.length === 0) return res.status(404).send('No property found with that ID.');
        const property = propResults[0];
        let agent = null;
        if (property.agentId) {
            const [agentResults] = await db.query("SELECT * FROM signin WHERE id = ? AND role = 'agent'", [property.agentId]);
            agent = agentResults.length > 0 ? agentResults[0] : null;
        }
        res.render('view-details', { property, isAdmin, userId: req.user.id, userEmail: req.user.email, agent });
    } catch (err) { console.error(err); res.status(500).send('Database query error.'); }
});

newapp2.get('/property-detail.html', (req, res) => res.render('login'));

// ==================== CONTACT ====================
newapp2.post('/contact', ensureAuthenticated, (req, res) => {
    const { name, email, phone, subject, message } = req.body;
    if (!name || !email || !phone || !message) return res.status(400).json({ success: false, message: 'All fields are required' });
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
    transporter.sendMail({
        from: `"G.O AREGHAN Real Estate Firm & Consultant" <${process.env.EMAIL_USER || 'esvgoddey@gmail.com'}>`,
        to: ADMIN_EMAILS.join(','),
        subject: `Contact Form: ${subject || 'New Inquiry'}`,
        html: `<h2>New Contact Message</h2><p><strong>Name:</strong> ${name}</p><p><strong>Email:</strong> ${email}</p><p><strong>Phone:</strong> ${phone}</p><p><strong>Subject:</strong> ${subject || 'N/A'}</p><p>${message.replace(/\n/g, '<br>')}</p>`
    }, (error, info) => {
        if (error) { console.error(error); return res.status(500).json({ success: false, message: 'Failed to send email.' }); }
        return res.status(200).json({ success: true, message: "Message sent successfully!" });
    });
});

newapp2.post('/detail-contact', ensureAuthenticated, async (req, res) => {
    const { name, email, phone, message, propertyId } = req.body;
    const userId = req.user.id;
    if (!name || !email || !phone || !message || !propertyId) return res.status(400).json({ success: false, message: 'All fields are required' });
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
    try {
        const [propResults] = await db.query("SELECT agentId FROM all_properties WHERE id = ?", [propertyId]);
        if (propResults.length === 0) return res.status(404).json({ success: false, message: 'Property not found' });
        const agentId = propResults[0].agentId;
        let recipientEmail = ADMIN_EMAILS.join(',');
        let receiverId = null;
        if (agentId) {
            const [agentResults] = await db.query("SELECT id, email FROM signin WHERE id = ? AND role = 'agent'", [agentId]);
            if (agentResults.length > 0 && agentResults[0].email) { recipientEmail = agentResults[0].email; receiverId = agentId; }
        }
        if (!receiverId) {
            const [adminResults] = await db.query("SELECT id FROM signin WHERE email = 'esvgoddey@gmail.com' LIMIT 1");
            if (adminResults.length === 0) {
                const [adminResults2] = await db.query("SELECT id FROM signin WHERE email = 'esvgoddey@gmail.com' LIMIT 1");
                if (adminResults2.length === 0) return res.status(500).json({ success: false, message: 'Admin not found' });
                receiverId = adminResults2[0].id;
            } else { receiverId = adminResults[0].id; }
        }
        transporter.sendMail({
            from: `"G.O AREGHAN Real Estate Firm & Consultant" <${process.env.EMAIL_USER || 'esvgoddey@gmail.com'}>`,
            to: recipientEmail,
            subject: 'New Contact Message from Property Detail Page',
            html: `<h2>New Contact Message</h2><p><strong>Name:</strong> ${name}</p><p><strong>Email:</strong> ${email}</p><p><strong>Phone:</strong> ${phone}</p><p>${message.replace(/\n/g, '<br>')}</p>`
        }, async (error) => {
            if (error) { console.error(error); return res.status(500).json({ success: false, message: 'Failed to send email.' }); }
            try {
                await db.query('INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)', [userId, receiverId, message]);
                res.redirect('/chat?success=Message sent! Redirecting to chat...');
            } catch (insertErr) { console.error(insertErr); res.status(500).json({ success: false, message: 'Message sent via email, but chat save failed.' }); }
        });
    } catch (err) { console.error(err); res.status(500).json({ success: false, message: 'Server error' }); }
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
        req.session.destroy(() => res.json({ success: true, message: 'Logged out successfully' }));
    });
});

// ==================== SOLD / UNSOLD / EDIT SOLD ====================
newapp2.get('/sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sell-page.html?error=Invalid property ID.');
    try {
        const [results] = await db.query('SELECT * FROM all_properties WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.redirect('/sell-page.html?error=Property not found.');
        const p = results[0];
        await db.query(
            `INSERT INTO sold_properties
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description,
             sqft, land_size, building_size, num_flats,
             image_data, video, documents, amount, title, rentSell, agentId, \`property-type\`)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                p.ownerName || '', p.ownerEmail || '', p.ownerPhone || '',
                p.propertyAddress || '', p.bedrooms || null, p.bathrooms || null,
                p.description || '', p.sqft || null,
                p.land_size || null, p.building_size || null, p.num_flats || null,
                normalizeImagePaths(p.image_data), p.video, p.documents || '',
                p.amount || null, p.title || null, p.rentSell || null,
                p.agentId, p['property-type'] || null
            ]
        );
        await db.query('DELETE FROM all_properties WHERE id = ?', [propertyId]);
        res.redirect(`/index.html?success=sold&title=${encodeURIComponent(p.title || '')}`);
    } catch (err) { console.error('Sold route error:', err); res.redirect('/sell-page.html?error=Failed to mark property as sold.'); }
});

newapp2.get('/sold-properties', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM sold_properties ORDER BY id DESC');
        res.render('sold-properties', { soldProperties: results, isAdmin: true });
    } catch (err) { console.error(err); res.redirect('/sold-properties?error=Failed to load sold properties.'); }
});

newapp2.get('/edit-sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.query.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sold-properties?error=Invalid property ID.');
    try {
        const [results] = await db.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.redirect('/sold-properties?error=Property not found.');
        res.render('edit-sold', { property: results[0], isAdmin: true });
    } catch (err) { console.error(err); res.redirect('/login'); }
});

newapp2.post('/update-sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.body.id;
    const u = {
        title:           req.body.title           || null,
        description:     req.body.description     || '',
        amount:          req.body.amount           || null,
        propertyAddress: req.body.propertyAddress  || '',
        bedrooms:        req.body.bedrooms         || null,
        bathrooms:       req.body.bathrooms        || null,
        sqft:            req.body.sqft             || null,
        land_size:       req.body.land_size        || null,
        building_size:   req.body.building_size    || null,
        num_flats:       req.body.num_flats ? parseInt(req.body.num_flats) : null,
        ownerName:       req.body.ownerName        || '',
        ownerEmail:      req.body.ownerEmail       || '',
        ownerPhone:      req.body.ownerPhone       || '',
        rentSell:        req.body.rentSell         || null,
        property_type:   req.body['property-type'] || null
    };
    try {
        await db.query(
            `UPDATE sold_properties SET title = ?, description = ?, amount = ?, propertyAddress = ?,
             bedrooms = ?, bathrooms = ?, sqft = ?, land_size = ?, building_size = ?, num_flats = ?,
             ownerName = ?, ownerEmail = ?, ownerPhone = ?, rentSell = ?, \`property-type\` = ? WHERE id = ?`,
            [u.title, u.description, u.amount, u.propertyAddress, u.bedrooms, u.bathrooms,
             u.sqft, u.land_size, u.building_size, u.num_flats,
             u.ownerName, u.ownerEmail, u.ownerPhone, u.rentSell, u.property_type, propertyId]
        );
        res.redirect('/sold-properties?success=Property updated successfully!');
    } catch (err) { console.error(err); res.redirect('/sold-properties?error=Failed to update property.'); }
});

newapp2.post('/unsold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.body.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sold-properties?error=Invalid property ID.');
    try {
        const [results] = await db.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId]);
        if (results.length === 0) return res.redirect('/sold-properties?error=Property not found.');
        const p = results[0];
        await db.query(
            `INSERT INTO all_properties
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description,
             sqft, land_size, building_size, num_flats,
             image_data, video, documents, amount, title, rentSell, \`property-type\`, agentId)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                p.ownerName || '', p.ownerEmail || '', p.ownerPhone || '',
                p.propertyAddress || '', p.bedrooms || null, p.bathrooms || null,
                p.description || '', p.sqft || null,
                p.land_size || null, p.building_size || null, p.num_flats || null,
                normalizeImagePaths(p.image_data), p.video, p.documents || '',
                p.amount || null, p.title || null, p.rentSell || null,
                p['property-type'] || null, p.agentId
            ]
        );
        await db.query('DELETE FROM sold_properties WHERE id = ?', [propertyId]);
        res.redirect('/sold-properties?success=Property moved back to active sales!');
    } catch (err) { console.error(err); res.redirect('/sold-properties?error=Failed to move property back.'); }
});

newapp2.post('/delete-sold', ensureAuthenticated, async (req, res) => {
    const propertyId = req.body.id;
    if (!propertyId || isNaN(propertyId)) return res.redirect('/sold-properties?error=Invalid property ID.');
    try {
        const [result] = await db.query('DELETE FROM sold_properties WHERE id = ?', [propertyId]);
        if (result.affectedRows === 0) return res.redirect('/sold-properties?error=Property not found.');
        res.redirect('/sold-properties?success=Property deleted successfully!');
    } catch (err) { console.error(err); res.redirect('/sold-properties?error=Failed to delete property.'); }
});

// ==================== MANAGE AGENTS ====================
newapp2.get('/manage-agent', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query(`
            SELECT s.id, s.firstName, s.middleName, s.lastName, s.email, s.phone,
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
                    UNION ALL SELECT agentId, status FROM sold_properties
                    UNION ALL SELECT agentId, status FROM sales_approval
                ) combined
                GROUP BY agentId
            ) stats ON s.id = stats.agentId
            WHERE s.role = 'agent'
        `);
        res.render('manage-agent', { agents: results, isAdmin: true });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
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
        transporter.sendMail({
            from: process.env.EMAIL_USER || 'esvgoddey@gmail.com',
            to: email,
            subject: 'Welcome to G.O AREGHAN Real Estate Firm & Consultant - Agent Account Created',
            html: `<h1>Welcome!</h1><p>Dear ${firstName} ${lastName},</p><p><strong>Email:</strong> ${email}<br><strong>Temporary Password:</strong> ${tempPassword}</p><p>Please change your password after logging in.</p>`
        }, (error) => { if (error) console.error('Email error:', error); });
        res.json({ success: true, message: 'Agent added successfully! Email sent with login details.' });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

newapp2.put('/manage/agent/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    const { firstName, middleName, lastName, email, phone } = req.body;
    if (!validator.isEmail(email)) return res.status(400).send('Invalid email address');
    try {
        await db.query('UPDATE signin SET firstName = ?, middleName = ?, lastName = ?, email = ?, phone = ? WHERE id = ? AND role = "agent"', [firstName, middleName || null, lastName, email, phone || null, id]);
        res.send('Agent updated successfully');
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

newapp2.delete('/manage/agent/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('DELETE FROM signin WHERE id = ? AND role = "agent"', [id]);
        res.send('Agent deleted successfully');
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

newapp2.post('/properties/approve/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM sales_approval WHERE id = ?', [id]);
        if (results.length === 0) return res.status(404).send('Property not found');
        const p = results[0];
        await db.query(
            `INSERT INTO all_properties
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description,
             sqft, land_size, building_size, num_flats,
             image_data, video, documents, amount, title, rentSell, \`property-type\`, agentId, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')`,
            [p.ownerName, p.ownerEmail, p.ownerPhone, p.propertyAddress, p.bedrooms || null, p.bathrooms || null,
             p.description, p.sqft || null, p.land_size || null, p.building_size || null, p.num_flats || null,
             normalizeImagePaths(p.image_data), p.video, p.documents || '', p.amount, p.title, p.rentSell,
             p.property_type, p.agentId]
        );
        await db.query('DELETE FROM sales_approval WHERE id = ?', [id]);
        res.send('Property approved');
    } catch (err) { console.error(err); res.status(500).send('Error'); }
});

newapp2.post('/properties/sell/:id', ensureAuthenticated, async (req, res) => {
    const { id } = req.params;
    try {
        const [results] = await db.query('SELECT * FROM all_properties WHERE id = ?', [id]);
        if (results.length === 0) return res.status(404).send('Property not found');
        const p = results[0];
        await db.query(
            `INSERT INTO sold_properties
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description,
             sqft, land_size, building_size, num_flats,
             image_data, video, documents, amount, title, rentSell, \`property-type\`, agentId, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sold')`,
            [p.ownerName, p.ownerEmail, p.ownerPhone, p.propertyAddress, p.bedrooms || null, p.bathrooms || null,
             p.description, p.sqft || null, p.land_size || null, p.building_size || null, p.num_flats || null,
             normalizeImagePaths(p.image_data), p.video, p.documents || '', p.amount, p.title, p.rentSell,
             p['property-type'], p.agentId]
        );
        await db.query('DELETE FROM all_properties WHERE id = ?', [id]);
        res.send('Property marked as sold');
    } catch (err) { console.error(err); res.status(500).send('Error'); }
});

// ==================== AGENT DASHBOARD & LISTINGS ====================
newapp2.get('/submit-listing', ensureAuthenticated, async (req, res) => {
    const agentId = req.user ? req.user.id : req.session.userId;
    if (!agentId) return res.status(400).send('Invalid session');
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
            db.query(`SELECT 'G.O AREGHAN Real Estate Firm & Consultant' AS siteTitle, 'esvgoddey@gmail.com' AS adminEmail`)
        ]);
        res.render('agent-dashboard', {
            totalProperties: totalPropsRows[0].totalProperties,
            totalAgents: totalAgentsRows[0].totalAgents,
            pendingApprovals: pendingRows[0].pendingApprovals,
            soldProperties: soldRows[0].soldProperties,
            activities, agents, approvals, customers, soldProps,
            siteTitle: settings[0].siteTitle, adminEmail: settings[0].adminEmail,
            username: req.session.firstName || (req.user && req.user.firstName),
            surname: req.session.lastName || (req.user && req.user.lastName),
            isAdmin: req.session.role === 'admin' || isAdminEmail(req.user?.email),
            isAgent: req.session.role === 'agent'
        });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

newapp2.get('/manage-listings', ensureAuthenticated, async (req, res) => {
    const agentId = req.user.id;
    if (!agentId) return res.status(400).send('Invalid session: Agent ID not found');
    try {
        const [[pendingListings], [approvedListings], [soldListings], [allListings]] = await Promise.all([
            db.query(`SELECT id, title, status FROM sales_approval WHERE agentId = ? AND status = 'pending'`, [agentId]),
            db.query(`SELECT id, title, status FROM all_properties WHERE agentId = ? AND status = 'approved'`, [agentId]),
            db.query(`SELECT id, title, status FROM sold_properties WHERE agentId = ?`, [agentId]),
            db.query(`(SELECT id, title, status FROM all_properties WHERE agentId = ?) UNION (SELECT id, title, status FROM sold_properties WHERE agentId = ?)`, [agentId, agentId])
        ]);
        res.render('manage-listing', { title: 'Manage Listings', pendingListings, approvedListings, soldListings, allListings });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

newapp2.get('/agent/listings/all', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, title, status FROM all_properties WHERE agentId = ?', [req.user.id]);
        res.json(results);
    } catch (err) { res.status(500).json({ error: 'Database error: ' + err.message }); }
});

newapp2.get('/agent/listings/pending', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, title, status FROM sales_approval WHERE agentId = ? AND status = "pending"', [req.user.id]);
        res.json(results);
    } catch (err) { res.status(500).json({ error: 'Database error: ' + err.message }); }
});

newapp2.get('/agent/listings/approved', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, title, status FROM all_properties WHERE agentId = ? AND status = "approved"', [req.user.id]);
        res.json(results);
    } catch (err) { res.status(500).json({ error: 'Database error: ' + err.message }); }
});

newapp2.get('/agent/listings/sold', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, title, status FROM sold_properties WHERE agentId = ?', [req.user.id]);
        res.json(results);
    } catch (err) { res.status(500).json({ error: 'Database error: ' + err.message }); }
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
    } catch (err) { console.error(err); res.status(500).json({ error: 'Database error' }); }
});

newapp2.post('/update-property/:id', requireAgent, async (req, res) => {
    const propertyId = req.params.id;
    const agentId = req.session.userId;
    const { title, description, amount, rentSell, property_type, status, bedrooms, bathrooms, land_size, building_size, num_flats } = req.body;
    try {
        const [findResults] = await db.query(`
            SELECT 'pending' AS tableName FROM sales_approval WHERE id = ? AND agentId = ?
            UNION SELECT 'approved' AS tableName FROM all_properties WHERE id = ? AND agentId = ?
            UNION SELECT 'sold' AS tableName FROM sold_properties WHERE id = ? AND agentId = ?
        `, [propertyId, agentId, propertyId, agentId, propertyId, agentId]);
        if (findResults.length === 0) return res.status(404).json({ error: 'Property not found or not owned by you' });
        const tableName = findResults[0].tableName;
        let table, propertyTypeColumn;
        if (tableName === 'pending')   { table = 'sales_approval';  propertyTypeColumn = 'property_type'; }
        else if (tableName === 'approved') { table = 'all_properties'; propertyTypeColumn = '`property-type`'; }
        else { table = 'sold_properties'; propertyTypeColumn = '`property-type`'; }
        await db.query(
            `UPDATE ${table} SET title = ?, description = ?, amount = ?, rentSell = ?,
             ${propertyTypeColumn} = ?, status = ?, bedrooms = ?, bathrooms = ?,
             land_size = ?, building_size = ?, num_flats = ?
             WHERE id = ? AND agentId = ?`,
            [title, description, amount, rentSell, property_type, status, bedrooms, bathrooms,
             land_size || null, building_size || null, num_flats ? parseInt(num_flats) : null,
             propertyId, agentId]
        );
        res.json({ success: true, message: 'Property updated successfully' });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Update failed: ' + err.message }); }
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
        const [[totalPropsRows], [pendingRows], [soldRows], [activities]] = await Promise.all([
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
            activities, chartData
        });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

// ==================== CHAT ROUTES ====================
newapp2.get('/chat', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const successMessage = req.query.success;
    const receiverId = req.query.receiverId;
    try {
        if (receiverId) {
            const [receiverResults] = await db.query("SELECT firstName, lastName, role FROM signin WHERE id = ?", [receiverId]);
            let receiverName = 'Unknown', isAgent = false;
            if (receiverResults.length > 0) {
                const r = receiverResults[0];
                receiverName = `${r.firstName || ''} ${r.lastName || ''}`.trim() || 'Unknown';
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
                receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || 'Unknown',
                isAgent: chat.role === 'agent',
                lastMessage: chat.lastMessage,
                lastMessageTime: chat.lastMessageTime
            }));
            res.render('chat', { messages: null, userId, receiverId: null, success: successMessage, receiverName: null, isAgent: null, chatList: processedChatList });
        }
    } catch (err) { console.error(err); res.status(500).send('Error loading chat'); }
});

newapp2.get('/customer-chat', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.redirect('/login');
    const clientId = req.user.id;
    try {
        const [agents] = await db.query('SELECT id FROM signin WHERE role = "agent" LIMIT 1');
        if (agents.length === 0) return res.send('No agents available.');
        res.render('customer-chat', { agentId: agents[0].id, clientId });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

newapp2.get('/api/staff-list', ensureAuthenticated, async (req, res) => {
    try {
        const [results] = await db.query("SELECT id, firstName, lastName, role FROM signin WHERE role IN ('admin', 'agent')");
        res.json(results);
    } catch (err) { console.error(err); res.status(500).json([]); }
});

newapp2.post('/chat/send', ensureAuthenticated, async (req, res) => {
    const { senderId, receiverId, message } = req.body;
    if (!senderId || !receiverId || !message) return res.status(400).json({ error: 'Missing required fields' });
    try {
        const [result] = await db.query('INSERT INTO chat_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())', [senderId, receiverId, message]);
        res.json({ success: true, messageId: result.insertId });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Error saving message' }); }
});

newapp2.get('/agent-chat', ensureAuthenticated, async (req, res) => {
    const userId = req.user.id;
    const receiverId = req.query.receiverId;
    try {
        if (receiverId) {
            const [receiverResults] = await db.query("SELECT firstName, lastName, role FROM signin WHERE id = ?", [receiverId]);
            let receiverName = 'Client', isClient = false;
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
    } catch (err) { console.error(err); res.status(500).send('Error loading chats'); }
});

newapp2.post('/agent-chat/send', ensureAuthenticated, async (req, res) => {
    const { senderId, receiverId, message } = req.body;
    if (!senderId || !receiverId || !message) return res.status(400).json({ error: 'Missing required fields' });
    try {
        const [result] = await db.query('INSERT INTO chat_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())', [senderId, receiverId, message]);
        res.json({ success: true, messageId: result.insertId });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Error saving message' }); }
});

newapp2.get('/admin-chat', ensureAuthenticated, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const userId = req.user.id;
    const receiverId = req.query.receiverId;
    try {
        if (receiverId) {
            const [receiverResults] = await db.query("SELECT firstName, lastName, role FROM signin WHERE id = ?", [receiverId]);
            let receiverName = 'Client', isClient = false;
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
    } catch (err) { console.error(err); res.status(500).send('Error loading chats'); }
});

// ==================== MISC ROUTES ====================
newapp2.get('/inquiries', ensureAuthenticated, async (req, res) => {
    if (req.session.role !== 'agent' && !isAdminEmail(req.user.email)) return res.redirect('/login');
    try {
        const [enquiries] = await db.query('SELECT * FROM enquiries ORDER BY timestamp DESC');
        res.render('enquiry', { enquiries });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

newapp2.get('/property-valuation', ensureAuthenticated, (req, res) => res.render('property-valuation'));

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || "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" });

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
            temperature: 0.3,
        });
        const raw = completion.choices[0].message.content;
        const match = raw.match(/\{[\s\S]*\}/);
        if (!match) throw new Error('Could not parse AI response');
        res.json(JSON.parse(match[0]));
    } catch (error) { console.error('Groq error:', error.message); res.status(500).json({ error: 'Valuation failed: ' + error.message }); }
});

newapp2.get('/gallery', async (req, res) => {
    try {
        const [card] = await db.query("SELECT * FROM all_properties ORDER BY id DESC");
        res.render('gallery', { card });
    } catch (err) { console.error(err); res.status(500).send('Server error'); }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;

connectWithRetry().then(() => {
    server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
}).catch(() => {
    server.listen(PORT, '0.0.0.0', () => console.log(`Server started (DB may be unavailable)`));
});
