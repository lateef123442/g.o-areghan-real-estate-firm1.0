// Step 1: Node modules export
const fs = require('fs');
const path = require('path');
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mysql = require('mysql2');
const multer = require('multer');
const cors = require('cors');
const passport = require('passport');
const session = require('express-session');
const bcrypt = require('bcrypt'); // For password hashing
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const validator = require('validator');
const http = require('http');
const socketIo = require('socket.io');
const axios = require('axios');  // This must be here
require('dotenv').config();
const Groq = require('groq-sdk');

const newapp2 = express();
const server = http.createServer(newapp2);  // Create HTTP server
const io = socketIo(server);  // Attach Socket.IO to the server (FIXED)

newapp2.use(cors());
newapp2.use(express.json());
newapp2.use(express.urlencoded({ extended: true }));


// Middleware for handling file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'uploads/';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Append timestamp to filename
    }
});

const upload = multer({ storage: storage });

// Set up session middleware
newapp2.use(session({
    secret: 'lateef.2008',
    resave: false,
    saveUninitialized: true
}));

// Authentication middleware
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}


// Initialize Passport.js
newapp2.use(passport.initialize());
newapp2.use(passport.session());

// Serialize user into the session
passport.serializeUser ((user, done) => {
    done(null, user.id); // Store user ID in session
});

// Deserialize user from the session
passport.deserializeUser ((id, done) => {
    // Find user by ID in the database
    connection.query('SELECT * FROM signin WHERE id = ?', [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]); // Populate req.user with user data
    });
});

// Configure your mail transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // or your email service
    auth: {
        user: 'ibarealestate2023@gmail.com', // your email
        pass: 'gwps gwod slos pjsl' // for Gmail, you might need an App Password
    }
});




// Database connection
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    port: Number(process.env.DB_PORT),
    multipleStatements: process.env.DB_MULTIPLE_STATEMENTS === 'true',
    queueLimit: Number(process.env.DB_QUEUE_LIMIT),
    ssl: false
});

// Connect to the database
connection.connect((error) => {
    if (error) {
        console.error('Database connection error:', error);
    } else {
        console.log('Database Connected!');
    }
});

// Socket.io for real-time chat
io.on('connection', (socket) => {

  socket.on('joinChat', (userId) => {
    socket.join(userId);   // join room with their userId
    console.log(`User ${userId} joined their room`);
  });

  socket.on('sendMessage', ({ senderId, receiverId, message }) => {
    // Save to database
    connection.query(
      'INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
      [senderId, receiverId, message],
      (err, result) => {
        if (err) {
          console.error('DB error:', err);
          return;
        }

        const timestamp = new Date();

        // ✅ Confirm back to SENDER — this re-enables the send button
        socket.emit('messageSent', { message, timestamp });

        // ✅ Send to RECEIVER if they are online
        io.to(String(receiverId)).emit('receiveMessage', {
          message,
          senderId,
          timestamp
        });
      }
    );
  });

});


// Set views file
newapp2.set('views', path.join(__dirname, 'views'));
newapp2.use('/img', express.static(path.join(__dirname, 'public', 'img')));
newapp2.use('/css', express.static(path.join(__dirname, 'public', 'css')));
newapp2.use('/plugins', express.static(path.join(__dirname, 'public', 'plugins')));
newapp2.use('/dist', express.static(path.join(__dirname, 'public', 'dist')));
newapp2.use('/js', express.static(path.join(__dirname, 'public', 'js')));
newapp2.use('/data', express.static(path.join(__dirname, 'public', 'data')));
newapp2.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Set view engine
newapp2.set('view engine', 'ejs');

// Body parser middleware
newapp2.use(bodyParser.json({ limit: '50mb' }));
newapp2.use(bodyParser.urlencoded({ limit: '50mb', extended: true, parameterLimit: 1000000 }));

// API to check login status (for frontend JS)
newapp2.get('/api/check-login', (req, res) => {
  if (req.user) {
    res.json({ loggedIn: true, username: req.user.firstName },);
  } else {
    res.json({ loggedIn: false });
  }
});

// Render website page
newapp2.get('/' ,(req, res) => {
      connection.query("SELECT * FROM all_properties LIMIT 3" , (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } 
        else {
            // Pass the card data and isAdmin flag to the sell-page template
            res.render('website', {
                card,
              
            });
        }
    });
});

// Assuming you have EJS set up as your view engine (from previous context)
newapp2.get('/website', (req, res) => {
    // Render your main website template (replace 'website' with your actual EJS file name)
    res.render('website', { /* Pass any data needed, e.g., title: 'IBA Real Estate' */ });
});

// Render login page
newapp2.get('/login', (req, res) => {
    res.render('login');
});


//render forgotten password
newapp2.get('/forgot-password.html', (req, res) => {
    res.render('forgotten-password');
});




newapp2.post('/submit', (req, res) => {
    const { firstName, middleName, lastName, email, phone, confirmPassword } = req.body;

    // Email validation
    if (!validator.isEmail(email)) {
        return res.status(400).render('invalid-email', {
            error: 'Please provide a valid email address'
        });
    }

    const checkEmailQuery = 'SELECT COUNT(*) AS count FROM signin WHERE email = ?';
    connection.query(checkEmailQuery, [email], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results[0].count > 0) {
            return res.render('invalid-email.ejs', {
                error: 'This email is already registered'
            });
        }

        // Hash password
        const hashedPassword = bcrypt.hashSync(confirmPassword, 10);

        // Updated INSERT query to explicitly set role as 'user'
        const sqlInsert = `INSERT INTO signin (firstName, middleName, lastName, email, phone, confirmPassword, role) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        connection.query(sqlInsert, [firstName, middleName, lastName, email, phone, hashedPassword, 'user'], (err) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Server error');
            }
            
            // Send welcome email
            const mailOptions = {
                from: 'lateefahmed3852@gmail.com',
                to: email,
                subject: 'Welcome to Iba Real Estate',
                html: `
                    <h1>Welcome to Iba Real Estate!</h1>
                    <p>Dear ${firstName} ${lastName},</p>
                    <p>Thank you for creating an account with Iba Real Estate. We're excited to help you find your dream property!</p>
                    <p>If you have any questions, don't hesitate to contact our support team.</p>
                    <p>Best regards,<br>The Iba Real Estate Team</p>
                `
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending email:', error);
                    // You might want to continue anyway since the registration succeeded
                } else {
                    console.log('Email sent:', info.response);
                }
            });

            console.log('User registered successfully');
            return res.render('valid-email');
        });
    });
});

// Display if email for registration already exists
newapp2.get('/invalid-reg-details', (req, res) => {
    res.render('signin-page');
});

// Display if email for registration doesn't exist
newapp2.get('/valid-reg-details', (req, res) => {
    res.render('login');
});

// If user already has an account
newapp2.get('/already-have-acct', (req, res) => {
    res.render('login');
});

// Routes for login
// Routes for login
newapp2.post('/dashboard', (req, res) => {
    const { email, password } = req.body;

    const sqlSelect = `SELECT * FROM signin WHERE email = ?`;
    connection.query(sqlSelect, [email], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            // Compare the hashed password
            const user = results[0];
            if (bcrypt.compareSync(password, user.confirmPassword)) {
                console.log("Valid login");
                req.login(user, (err) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).send('Login error');
                    }

                    // Check if the user is the specific admin
                    if (email === 'ibarealestate2023@gmail.com') {
                        req.session.isAdmin = true; // Set admin flag in session
                        req.session.isAgent = false; // Ensure agent is false
                        return res.render('valid-login', {
                            username: user.firstName,
                            surname: user.lastName,
                            isAdmin: req.session.isAdmin,
                            isAgent: req.session.isAgent
                        });
                    } 
                    // Check if the user is an agent
                    else if (user.role === 'agent') {
                        req.session.isAgent = true; // Set agent flag in session
                        req.session.isAdmin = false; // Ensure admin is false
                        req.session.userId = user.id; // Store the numeric database ID here
                        req.session.role = 'agent';
                        req.session.firstName = user.firstName; // Optional: store name for display
                        req.session.lastName = user.lastName;

                        // Fetch agent-specific data for dashboard
                        const agentId = user.id;
                        const queries = [
                            // Total Properties (all tables combined, count unique properties)
                            `SELECT COUNT(*) AS totalProperties FROM (
                                SELECT id FROM all_properties WHERE agentId = ?
                                UNION
                                SELECT id FROM sold_properties WHERE agentId = ?
                                UNION
                                SELECT id FROM sales_approval WHERE agentId = ?
                            ) AS combined`,
                            // Total Agents (count all agents, or set to 1 for self-view)
                            `SELECT COUNT(*) AS totalAgents FROM signin WHERE role = 'agent'`,
                            // Pending Approvals (from sales_approval where status = 'pending')
                            `SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`,
                            // Sold Properties (from sold_properties)
                            `SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`,
                            // Recent Activities (from all_properties, ordered by created_at)
                            `SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`,
                            // Agents (agent's own data)
                            `SELECT id, firstName, lastName, email, phone FROM signin WHERE id = ?`,
                            // Approvals (agent's pending properties from sales_approval)
                            `SELECT s.id, s.title, s.status, u.firstName AS agentName FROM sales_approval s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ? AND s.status = 'pending'`,
                            // Customers (from signin where role = 'user', limit for display)
                            `SELECT firstName, lastName, email, phone, role FROM signin WHERE role = 'user' LIMIT 10`,
                            // Sold Props (from sold_properties)
                            `SELECT s.title, u.firstName AS agentName, s.amount, s.created_at AS soldDate FROM sold_properties s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ?`,
                            // Settings (placeholder, can be from a settings table or hardcoded)
                            `SELECT 'IBA Real Estate' AS siteTitle, 'admin@example.com' AS adminEmail`
                        ];

                        const queryPromises = queries.map((query, index) => {
                            return new Promise((resolve, reject) => {
                                const params = index === 0 ? [agentId, agentId, agentId] :
                                               index === 1 ? [] :
                                               index === 2 ? [agentId] :
                                               index === 3 ? [agentId] :
                                               index === 4 ? [agentId] :
                                               index === 5 ? [agentId] :
                                               index === 6 ? [agentId] :
                                               index === 7 ? [] :
                                               index === 8 ? [agentId] :
                                               [];
                                connection.query(query, params, (err, results) => {
                                    if (err) reject(err);
                                    else resolve(results);
                                });
                            });
                        });

                        Promise.all(queryPromises).then((results) => {
                            const data = {
                                totalProperties: results[0][0].totalProperties,
                                totalAgents: results[1][0].totalAgents,
                                pendingApprovals: results[2][0].pendingApprovals,
                                soldProperties: results[3][0].soldProperties,
                                activities: results[4],
                                agents: results[5],
                                approvals: results[6],
                                customers: results[7],
                                soldProps: results[8],
                                siteTitle: results[9][0].siteTitle,
                                adminEmail: results[9][0].adminEmail,
                                username: user.firstName,
                                surname: user.lastName,
                                isAdmin: req.session.isAdmin,
                                isAgent: req.session.isAgent
                            };
                            return res.render('agent-dashboard', data);
                        }).catch((err) => {
                            console.error('Data fetch error:', err);
                            return res.status(500).send('Server error');
                        });
                    } 
                    // Default to user
                    else {
                        req.session.isAdmin = false;
                        req.session.isAgent = false;
                        connection.query("SELECT * FROM all_properties LIMIT 3", (err, card) => {
                            if (err) {
                                console.error(err.message);
                                return res.status(500).send('Server error');
                            }
                            return res.render('website', { card });
                        });
                    }
                });
            } else {
                console.log("Invalid login");
                res.render('invalid-login');
            }
        } else {
            console.log("Invalid login");
            res.render('invalid-login');
        }
    });
});

// Valid login details
newapp2.get('/valid-login', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

            // Query to get the sell images
            connection.query("SELECT * FROM all_properties", (err, card) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Server error');
                } else {
                    // Pass the user details and isAdmin flag to the index template
                    res.redirect('track-sales.html');
                }
            });
        } else {
            return res.status(404).send('User  not found');
        }
    });
});





// Invalid login
newapp2.get('/invalid-login', (req, res) => {
    res.render('login');
});

// Navigation begins
// Index
newapp2.get('/index.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query("SELECT * FROM all_properties", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } else {
            // Pass the card data and isAdmin flag to the index template
            res.render('index', {
                card,
                isAdmin // Pass the isAdmin flag
            });
        }
    });
});


// Buy page
newapp2.get('/buy-page.html', ensureAuthenticated, (req, res)=> {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query("SELECT * FROM all_properties WHERE rentSell = 'sell'", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error'); // Send a 500 error response
        } else {
            // Render the buy page and pass the card data and isAdmin flag
            res.render('buy-page', {
                card,
                isAdmin // Pass the isAdmin flag
            });
        }
    });
});


// Home improvement
newapp2.get('/home-improvemet-page.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    // Render the home improvement page and pass the isAdmin flag
    res.render('home-improvemet-page', {
        isAdmin // Pass the isAdmin flag
    });
});


// Sell page
newapp2.get('/sell-page.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query("SELECT * FROM all_properties", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } else {
            // Pass the card data and isAdmin flag to the sell-page template
            res.render('sell-page', {
                card,
                isAdmin // Pass the isAdmin flag
            });
        }
    });
});


// Rent page
newapp2.get('/rent-page.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query("SELECT * FROM all_properties WHERE rentSell = 'rent'", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } else {
            // Pass the card data and isAdmin flag to the rent-page template
            res.render('rent-page', {
                card,
                isAdmin // Pass the isAdmin flag
            });
        }
    });
});


// Message page
newapp2.get('/message-page.html', ensureAuthenticated, (req, res)=> {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    // Render the message page and pass the isAdmin flag
    res.render('message-page', {
        isAdmin // Pass the isAdmin flag
    });
});


// Setting page
newapp2.get('/setting-page.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    // Render the setting page and pass the isAdmin flag
    res.render('setting-page', {
        isAdmin // Pass the isAdmin flag
    });
});


//sales-approval
newapp2.get('/sales-approval.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query("SELECT * FROM sales_approval", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } else {
            // Pass the card data and isAdmin flag to the sales-approval template
            res.render('sales-approval', {
                card,
                isAdmin // Pass the isAdmin flag
            });
        }
    });
});




// Notification
newapp2.get('/notificatin-page.html', ensureAuthenticated, (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    // Render the notification page and pass the isAdmin flag
    res.render('notification-page', {
        isAdmin // Pass the isAdmin flag
    });
});


//request tour
newapp2.get('/tour-requested.html', ensureAuthenticated, (req, res)=> {
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    const sqlQuery = `
        SELECT *, (SELECT COUNT(*) FROM request_tour) AS count 
        FROM request_tour`; // Adjust the query as per your table structure

    connection.query(sqlQuery, (err, results) => {
        if (err) {
            console.error('Error fetching tour requests:', err.message);
            return res.status(500).send('Database query error.');
        }

        // Get the count from the result
        const rowCount = results.length > 0 ? results[0].count : 0; // Ensure there's at least one result

        // Render the requested tour page with the fetched data and isAdmin flag
        res.render('requested-tour', {
            card: results,
            rowCount,
            isAdmin // Pass the isAdmin flag
        });
    });
});



// Profile
newapp2.get('/profile-page.html', ensureAuthenticated, (req, res) => {
    // Check if the user is authenticated
    if (!req.user || !req.user.id) {
        return res.redirect('/login'); // Redirect to login if not authenticated
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query('SELECT id, firstName, middleName, lastName, email, phone FROM signin WHERE id = ?', 
        [req.user.id], (err, results) => {
            if (err) {
                console.error(err); // Log the error for debugging
                return res.status(500).send('Internal Server Error'); // Send a 500 error response
            }

            // Check if results are empty
            if (results.length === 0) {
                return res.status(404).send('User  not found'); // Handle case where user is not found
            }

            // Render the profile page and pass the user data and isAdmin flag
            res.render('profile-page', {
                id: results[0].id,
                firstName: results[0].firstName,
                middleName: results[0].middleName,
                lastName: results[0].lastName,
                email: results[0].email,
                phone: results[0].phone,
                isAdmin // Pass the isAdmin flag
            });
        });
});

// Render sales-tracker
// Route: Track Sales Dashboard (GET /track-sales)
newapp2.get('/track-sales.html', ensureAuthenticated, (req, res) => {
   /* if (!req.user || req.user.role !== 'admin') {
        return res.redirect('/?error=Unauthorized access. Admins only.');
    }*/

    // Object to hold all stats
    const stats = {};

    // Helper function to run queries sequentially (using callbacks for your mysql setup)
    function runQueries(callback) {
        let queryCount = 0;
        const totalQueries = 7;  // Pending, All Sales, Sold, Customers, This Month, Property Types, Monthly Sold

        function checkDone() {
            queryCount++;
            if (queryCount === totalQueries) {
                callback();
            }
        }

        // 1. Pending Sales from sales_approval
        connection.query("SELECT COUNT(*) as count FROM sales_approval", (err, results) => {
            if (err) {
                console.error('Pending sales query error:', err);
                stats.pendingSales = 0;
            } else {
                stats.pendingSales = results[0].count || 0;
            }
            checkDone();
        });

        // 2. All Sales from sold_properties (total completed sales)
        connection.query("SELECT COUNT(*) as count FROM all_properties", (err, results) => {
            if (err) {
                console.error('All sales query error:', err);
                stats.allSales = 0;
            } else {
                stats.allSales = results[0].count || 0;
            }
            checkDone();
        });

          // 2. All Sales from sold_properties (total completed sales)
        connection.query("SELECT COUNT(*) as count FROM sold_properties", (err, results) => {
            if (err) {
                console.error('All sales query error:', err);
                stats.soldProperties = 0;
            } else {
                stats.soldProperties = results[0].count || 0;
            }
            checkDone();
        });

  

        // 4. All Customers from signin (unique emails)
        connection.query("SELECT COUNT(DISTINCT email) as count FROM signin", (err, results) => {
            if (err) {
                console.error('Customers query error:', err);
                stats.customers = 0;
            } else {
                stats.customers = results[0].count || 0;
            }
            checkDone();
        });

        // 5. Sold This Month from sold_properties
        connection.query(
            "SELECT COUNT(*) as count FROM sold_properties WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())",
            (err, results) => {
                if (err) {
                    console.error('Sold this month query error:', err);
                    stats.soldThisMonth = 0;
                } else {
                    stats.soldThisMonth = results[0].count || 0;
                }
                checkDone();
            }
        );

        // 6. Property Types Counts from all_properties
        connection.query(
            "SELECT `property-type` as type, COUNT(*) as count FROM all_properties WHERE `property-type` IN ('Plots of Land', 'Duplex/Bangalow/Storey building', 'Self Contain') GROUP BY `property-type`",
            (err, results) => {
                if (err) {
                    console.error('Property types query error:', err);
                    stats.propertyTypes = [];
                } else {
                    stats.propertyTypes = results;  // Array: [{type: 'Plots of Land', count: 5}, ...]
                }
                checkDone();
            }
        );

        // 7. Monthly Sold (last 12 months for line chart)
  // 7. Monthly Sold Properties (Last 12 Months) - Enhanced with readable labels
connection.query(
    "SELECT DATE_FORMAT(created_at, '%b %Y') as month, COUNT(*) as count " +
    "FROM sold_properties " +
    "WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH) " +
    "GROUP BY DATE_FORMAT(created_at, '%Y-%m') " +  // Group by actual YYYY-MM for accuracy
    "ORDER BY DATE_FORMAT(created_at, '%Y-%m') ASC",  // Order by actual date
    (err, results) => {
        if (err) {
            console.error('Monthly sold query error:', err);
            stats.monthlySold = [];
        } else {
            // Post-process: Ensure month is formatted (MySQL '%b %Y' gives 'Oct 2024')
            stats.monthlySold = results.map(row => ({
                month: row.month,  // Already 'Oct 2024'
                count: parseInt(row.count) || 0
            }));
            console.log('Monthly sold fetched:', stats.monthlySold);  // Debug: e.g., [{month: 'Oct 2025', count: 3}]
        }
        checkDone();
    }
);
    }

    runQueries(() => {
        console.log('Track Sales Stats:', stats);
        res.render('sales-tracker', { 
            stats, 
            isAdmin: true 
        });
    });
});


// Navigation ends

// Need to sign in
newapp2.get('/register.html', (req, res) => {
    res.render('signin-page');
});

// Route for selling a property
newapp2.post('/upload', upload.fields([
    { name: 'image', maxCount: 10 },  // max 10 images
    { name: 'video', maxCount: 5 }    // max 5 videos
]), (req, res) => {
    // Check if user is authenticated
    if (!req.user) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.user.id;

    // Query to get the user's role from signin table
    connection.query('SELECT role FROM signin WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user role:', err);
            return res.status(500).send('Server error');
        }

        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const role = results[0].role;
        // As per instruction: if agent, use userId as agentId; if not, still use userId as agentId
        const agentId = userId;

        // Extract form data
        const {
            ownerName, ownerEmail, ownerPhone, propertyAddress,
            bedrooms, bathrooms, sqft, description, title,
            rentSell, amount, property_type
        } = req.body;

        // Extract image paths (assuming multer saves to disk, adjust if storing buffers)
        const imagePaths = req.files.image ? req.files.image.map(file => file.path).join(',') : '';

        // Extract video paths
        const videoPaths = req.files.video ? req.files.video.map(file => file.path).join(',') : '';

        // SQL Insert statement with agentId
        const sql = `
            INSERT INTO sales_approval 
            (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft, image_data, video, description, title, rentSell, amount, property_type, agentId) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            ownerName, ownerEmail, ownerPhone, propertyAddress,
            bedrooms, bathrooms, sqft, imagePaths, videoPaths,
            description, title, rentSell, amount, property_type, agentId
        ];

        connection.query(sql, values, (err) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).send('Error inserting data: ' + err.message);
            }
              res.json({ 
            success: true, 
            message: 'Property uploaded successfully! Your listing has been submitted for review.'
        });
        });
    });
});

// Sales progress before sending to admin
newapp2.get('/sales-completed', (req, res) => {
    // Check if the user is logged in
    if (!req.user) {
        return res.redirect('/login');
    }

    const userEmail = req.user.email; // Get the user email from the session

    // Determine if the user is an admin based on their email
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    connection.query("SELECT * FROM all_properties", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } else {
            // Pass the card data and isAdmin flag to the index template
            res.render('sell-page', {
                card,
                isAdmin // Pass the isAdmin flag
            });
        }
    });
});




newapp2.get('/sales-approved', (req, res) => {
    // Ensure req.user exists (authentication middleware should set this)
    if (!req.user) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.user.id; 
    const userEmail = req.user.email;

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            return res.status(500).send('Server error');
        }

        if (results.length === 0) {
            return res.status(404).send('User  not found');
        }

        const user = results[0];

        // Determine if the user is an admin based on their email
        const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

        // Query to get all signin records (or change to your intended table)
        connection.query("SELECT * FROM signin", (err, card) => {
            if (err) {
                console.error('Error fetching signin records:', err.message);
                return res.status(500).send('Server error');
            }

            // Render the 'sales-approval' view and pass data
            return res.redirect('sales-approval.html',);
        });
    });
});

newapp2.get('/sales-declined', (req, res) => {
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session
    

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
    connection.query("SELECT * FROM signin", (err, card) => {
            if (err) {
                console.error('Error fetching signin records:', err.message);
                return res.status(500).send('Server error');
            }

            // Render the 'sales-approval' view and pass data
            return res.redirect('sales-approval.html',);
        });
}
    });
});


// Request tour
newapp2.get('/request-tour', (req, res) => {
    const propertyId = req.query.id; // Get the ID from the query parameters
    // Check if the ID is provided
    if (!propertyId) {
        return res.status(400).send('Property ID is required.');
    }
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session
    

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
            const propertyId = req.query.id;
    // Query the database for the specific property
    connection.query("SELECT * FROM all_properties WHERE id = ?", [propertyId], (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Database query error.');
        }
        // Check if any property was found
        if (card.length > 0) {
            // Render the request-toutour page with the property data
            res.render('request-tour', { property: card[0] ,isAdmin, // Pass the isAdmin flag
                userId: user.id,
                userEmail: user.email}); // Pass the property data to the template
        } else {
            res.status(404).send('No property found with that ID.');
        }
    });
}
    });
});



newapp2.get('/view', ensureAuthenticated, (req, res) => {
     // Get the ID from the query parameters
    // Check if the user is logged in
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session
    

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
            const propertyId = req.query.id;
            // Query the database for the specific property
    connection.query("SELECT * FROM sales_approval WHERE id = ?", [propertyId], (err, card) => {
                if (err) {
                    console.error(err.message);
                    return res.status(500).send('Database query error.');
                } else {
                    if (card.length > 0) {
                        // Render the request-tour page with the property data
                    res.render('request-tour', {
                        property: card[0],
                        isAdmin, // Pass the isAdmin flag
                        userId: user.id,
                        userEmail: user.email
                    });
                    
                }
                else {
                    res.status(404).send('No property found with that ID.');
                }
                }
            });
        } else {
            return res.status(404).send('User  not found');
        }
    });
});

// Submit tour route
newapp2.post('/submit-tour', (req, res) => {
    const { name, email, phone, date, time } = req.body;
    // Insert data into the database
    const sql = 'INSERT INTO request_tour (name, email, phone, date, time) VALUES (?, ?, ?, ?, ?)';
    const values = [name, email, phone, date, time];
    connection.query(sql, values, (err) => {
        if (err) {
            return res.status(500).send('Error inserting data: ' + err);
        }
        res.render('tour-submitted');
    });
});

// Tour submitted route
newapp2.get('/tour-submitted', (req, res) => {
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session
    

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
            const propertyId = req.query.id;
    connection.query("SELECT * FROM all_properties", (err, card) => {
        if (err) {
            console.error(err.message);
        } else {
            res.render('index', { card,isAdmin, // Pass the isAdmin flag
                userId: user.id,
                userEmail: user.email, });
        }
    });
}
    });
});

// Save home improvement into the database
newapp2.post('/improvement-request-form', (req, res) => {
    const { name, email, phone, message } = req.body;
    // Insert data into the database
    const sql = 'INSERT INTO homeImprovement (name, email, phone, message) VALUES (?, ?, ?, ?)';
    const values = [name, email, phone, message];
    connection.query(sql, values, (err) => {
        if (err) {
            return res.status(500).send('Error inserting data: ' + err);
        }
        res.render('tour-submitted');
    });
}); 


//edit profile rout
newapp2.get('/edit-profile', (req, res) => {
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session

      // Query to get the user's details from the signin database
      const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
      connection.query(sqlSelect, [userId], (err, results) => {
          if (err) {
              console.error(err.message);
              return res.status(500).send('Server error');
          }
  
          if (results.length > 0) {
              const user = results[0]; // Get the user details
  
              // Determine if the user is an admin based on their email
              const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

              res.render('setting-page', { isAdmin, // Pass the isAdmin flag
                 });
        
    
          }
          });
});

// Update profile route
newapp2.post('/update-profile', (req, res) => {
    const { firstName, middleName, lastName, email, phone, currentPassword } = req.body;
    const userId = req.user.id; // Assuming user is authenticated

    // Fetch the current user's hashed password from the database
    connection.query('SELECT confirmPassword FROM signin WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching user data');
        }

        if (results.length === 0) {
            return res.status(404).send('User  not found');
        }

        const hashedPassword = results[0].confirmPassword;

        // Compare the entered password with the hashed password
        if (!bcrypt.compareSync(currentPassword, hashedPassword)) {
            return res.status(401).send('Current password is incorrect'); // Unauthorized
        }

        // If the password matches, update the user data
        const sql = `UPDATE signin 
                     SET firstName = ?, middleName = ?, lastName = ?, email = ?, phone = ?
                     WHERE id = ?`;
        
        connection.query(sql, [firstName, middleName, lastName, email, phone, userId], (err) => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error updating profile');
            }
            res.redirect('/profile-page.html'); // Redirect to profile page after update
        });
    });
});


// Route to send message
newapp2.post('/message', (req, res) => {
    console.log('Request body:', req.body); // Log the entire request body

    // Validate message input
    const message = req.body.message;
    if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'Invalid message format' });
    }

    const userId = req.user.id;
    console.log('Received message:', message);
    console.log('User  ID:', userId);

    // Retrieve user details from the database
    connection.query('SELECT firstName, email FROM signin WHERE id = ?', [userId], (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User  not found' });
        }

        const user = results[0];

        // Email options
        const mailOptions = {
            from: user.email,
            to: 'ibarealestate2023@gmail.com', // Creator's email
            subject: `New Message from ${user.firstName}`,
            text: message,
            html: `<p><strong>From:</strong> ${user.firstName} (${user.email})</p><p><strong>Message:</strong></p><p>${message}</p>`,
        };

        // Send email
        transporter.sendMail(mailOptions, (err) => {
            if (err) {
                console.error('Error sending email:', err);
                return res.status(500).json({ error: 'Failed to send message' });
            }
            res.status(200).json({ success: true, message: 'Message sent successfully' });
        });
    });
});


// sales approve route
newapp2.get('/approve', (req, res) => {
    const propertyId = req.query.id; // Get the ID from query

    // Check if the ID is provided
    if (!propertyId) {
        return res.status(400).send('Property ID is required.');
    }

    // Query the database for the specific property
    connection.query(
        "SELECT * FROM sales_approval WHERE id = ?",
        [propertyId],
        (err, results) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Database query error.');
            }

            // Check if any property was found
            if (results.length === 0) {
                return res.status(404).send('No property found with that ID.');
            }

            const property = results[0];

            // Insert the property into the all_properties table with correct column order and status
            const sqlInsertSell = `
                INSERT INTO all_properties 
                (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, sqft, image_data, video, description, title, rentSell, agentId, amount, \`property-type\`, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')
            `;
            connection.query(
                sqlInsertSell,
                [
                    property.ownerName,
                    property.ownerEmail,
                    property.ownerPhone,
                    property.propertyAddress,
                    property.bedrooms,
                    property.bathrooms,
                    property.sqft,
                    property.image_data,
                    property.video,
                    property.description,
                    property.title,
                    property.rentSell,
                    property.agentId,        // Correct position for agentId
                    property.amount,         // Correct position for amount
                    property.property_type   // Correct position for property-type
                ],
                (err) => {
                    if (err) {
                        console.error(err.message);
                        return res.status(500).send('Error inserting into all_properties.');
                    }

                    // Insert the amount into the total_amount table
                    const sqlInsertTotal = `INSERT INTO total_amount (amount) VALUES (?)`;
                    connection.query(
                        sqlInsertTotal,
                        [property.amount],
                        (err) => {
                            if (err) {
                                console.error(err.message);
                                return res.status(500).send('Error inserting into total_amount.');
                            }

                            // Now delete the property from the sales_approval table
                            const sqlDelete = `DELETE FROM sales_approval WHERE id = ?`;
                            connection.query(sqlDelete, [propertyId], (err) => {
                                if (err) {
                                    console.error(err.message);
                                    return res.status(500).send('Error deleting from sales_approval.');
                                }

                                return res.render('sales-approved-successfully');
                            });
                        }
                    );
                }
            );
        }
    );
});


//decline sales route
newapp2.get('/decline', (req, res) => {
    const propertyId =  req.query.id; // Get the ID from the request body
    
    // Check if the ID is provided
    if (!propertyId) {
        return res.status(400).send('Property ID is required.');
    }

    // Query the database for the specific property
    connection.query("SELECT * FROM sales_approval WHERE id = ?", [propertyId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Database query error.');
        }

        // Check if any property was found
        if (results.length > 0) {
            const property = results[0];
            
                // Now delete the property from the sales_approval table
                const sqlDelete = `DELETE FROM sales_approval WHERE id = ?`;
                connection.query(sqlDelete, [propertyId], (err,) => {
                    if (err) {
                        console.error(err.message);
                        return res.status(500).send('Error deleting from sales_approval.');
                    }

                    return res.render('sales-declined-successfully');
                });
        }
        
    });
});



// Route to fetch customer details
newapp2.get('/view-customers.html', (req, res) => {
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session

      // Query to get the user's details from the signin database
      const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
      connection.query(sqlSelect, [userId], (err, results) => {
          if (err) {
              console.error(err.message);
              return res.status(500).send('Server error');
          }
  
          if (results.length > 0) {
              const user = results[0]; // Get the user details
  
              // Determine if the user is an admin based on their email
              const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
    const sqlQuery = `
        SELECT id, firstName, middleName, email, phone, 
               (SELECT COUNT(*) FROM signin) AS count 
        FROM signin`; // Adjust the query as per your table structure

    connection.query(sqlQuery, (err, results) => {
        if (err) {
            console.error('Error fetching customer data:', err);
            return res.status(500).send('Database query error.');
        }

        // Get the count from the result
        const rowCount = results.length > 0 ? results[0].count : 0; // Ensure there's at least one result

        // Render the customer management page with the fetched data
        res.render('customers', { customers: results, rowCount ,isAdmin, // Pass the isAdmin flag
            userId: user.id,
            userEmail: user.email,rowCount  });
    });
}
      });
});


// Route to approve a tour request
newapp2.get('/approve-tour', (req, res) => {

    const tourId = req.query.id;
    // Fetch the tour details to get the email
    connection.query('SELECT * FROM request_tour WHERE id = ?', [tourId], (err, results) => {
        if (err) {
            console.error('Error fetching tour details:', err);
            return res.status(500).send('Database query error.');
        }

        if (results.length === 0) {
            return res.status(404).send('Tour not found.');
        }

        const tour = results[0];

        // Send email notification
        const mailOptions = {
            from: 'your-email@gmail.com',
            to: tour.email,
            subject: 'Tour Request Approved',
            text: `Dear ${tour.name},\n\nYour tour request has been approved.\n\nBest regards,\nIba Real Estate`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).send('Error sending email.');
            }

            // Delete the tour request from the database
            connection.query('DELETE FROM request_tour WHERE id = ?', [tourId], (err) => {
                if (err) {
                    console.error('Error deleting tour request:', err);
                    return res.status(500).send('Database query error.');
                }

                
               return res.render('tour-approved-successfully');
            });
        });
    });
});

// Route to decline a tour request
newapp2.get('/decline-tour', (req, res) => {
    const tourId = req.query.id;

    // Fetch the tour details to get the email
    connection.query('SELECT * FROM request_tour WHERE id = ?', [tourId], (err, results) => {
        if (err) {
            console.error('Error fetching tour details:', err);
            return res.status(500).send('Database query error.');
        }

        if (results.length === 0) {
            return res.status(404).send('Tour not found.');
        }

        const tour = results[0];

        // Send email notification
        const mailOptions = {
            from: 'your-email@gmail.com',
            to: tour.email,
            subject: 'Tour Request Declined',
            text: `Dear ${tour.name},\n\nYour tour request has been declined.\n\nBest regards,\nIba Real Estate`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).send('Error sending email.');
            }

            // Delete the tour request from the database
            connection.query('DELETE FROM request_tour WHERE id = ?', [tourId], (err) => {
                if (err) {
                    console.error('Error deleting tour request:', err);
                    return res.status(500).send('Database query error.');
                }

               
               return res.render('tour-declined-successfully');
            });
        });
    });
});


// route for successful tour approval
newapp2.get('/tour-approved-successfully', (req, res) => {
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session
    

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
      
            // Query the database for the specific property
    const sqlQuery = `
    SELECT *, (SELECT COUNT(*) FROM request_tour) AS count 
    FROM request_tour`; // Adjust the query as per your table structure

connection.query(sqlQuery, (err, results) => {
    if (err) {
        console.error('Error fetching tour requests:', err.message);
        return res.status(500).send('Database query error.');
    }

    // Get the count from the result
    const rowCount = results.length > 0 ? results[0].count : 0; // Ensure there's at least one result

    // Render the requested tour page with the fetched data
    res.render('requested-tour', { card: results, isAdmin, // Pass the isAdmin flag
        userId: user.id,
        userEmail: user.email,rowCount });
});
}
    }); 
});



// route for successful tour approval
newapp2.get('/tour-declined-successfully', (req, res) => {
    const userId = req.user.id; // Get the user ID from the session
    const userEmail = req.user.email; // Get the user email from the session
    

    // Query to get the user's details from the signin database
    const sqlSelect = `SELECT * FROM signin WHERE id = ?`;
    connection.query(sqlSelect, [userId], (err, results) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        if (results.length > 0) {
            const user = results[0]; // Get the user details

            // Determine if the user is an admin based on their email
            const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
         

    const sqlQuery = `
    SELECT *, (SELECT COUNT(*) FROM request_tour) AS count 
    FROM request_tour`; // Adjust the query as per your table structure

connection.query(sqlQuery, (err, results) => {
    if (err) {
        console.error('Error fetching tour requests:', err.message);
        return res.status(500).send('Database query error.');
    }

    // Get the count from the result
    const rowCount = results.length > 0 ? results[0].count : 0; // Ensure there's at least one result

    // Render the requested tour page with the fetched data
    res.render('requested-tour', { card: results, rowCount,isAdmin, // Pass the isAdmin flag
        userId: user.id,
        userEmail: user.email,rowCount  });
});
}
    });
});


newapp2.get('/search', ensureAuthenticated, (req, res) => {
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email;
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    // Extract search query parameters
    const { location, min_price, max_price, min_beds, min_baths } = req.query;

    // Start SQL query
    let sql = "SELECT * FROM all_properties WHERE 1=1";
    let values = [];

    // Add filters dynamically
    if (location) {
        sql += " AND propertyAddress LIKE ?";
        values.push(`%${location}%`);
    }
    if (min_price) {
        sql += " AND amount >= ?";
        values.push(min_price);
    }
    if (max_price) {
        sql += " AND amount <= ?";
        values.push(max_price);
    }
    if (min_beds) {
        sql += " AND bedrooms >= ?";
        values.push(min_beds);
    }
    if (min_baths) {
        sql += " AND bathrooms >= ?";
        values.push(min_baths);
    }

    // Run query
    connection.query(sql, values, (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }
        res.render('index', {
            card,
            isAdmin
        });
    });
});


// Buy Search Route
newapp2.get('/buy-search-form', ensureAuthenticated, (req, res) => {
    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }

    const userEmail = req.user.email;
    const isAdmin = userEmail === 'ibarealestate2023@gmail.com';

    // Extract query params from form
    const { location,  min_price,  max_price,  min_beds,  min_baths } = req.query;

    // Base query
    let query = "SELECT * FROM all_properties WHERE rentSell = 'sell'";
    let queryParams = [];

    // Apply filters if provided
    if (location && location.trim() !== '') {
        query += " AND propertyAddress LIKE ?";
        queryParams.push(`%${location}%`);
    }
    if (min_price && !isNaN(min_price)) {
        query += " AND amount >= ?";
        queryParams.push(parseInt(minPrice));
    }
    if (max_price && !isNaN(max_price)) {
        query += " AND amount <= ?";
        queryParams.push(parseInt(max_price));
    }
    if (min_beds && !isNaN(min_beds)) {
        query += " AND bedrooms >= ?";
        queryParams.push(parseInt(min_beds));
    }
    if (min_baths && !isNaN(min_baths)) {
        query += " AND bathrooms >= ?";
        queryParams.push(parseInt(min_baths));
    }

    // Run the query
    connection.query(query, queryParams, (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        }

        // Render same buy-page with filtered results
        res.render('buy-page', {
            card,
            isAdmin
        });
    });
});


// customer Sell page
newapp2.get('/customer-buy-page.html', (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'sell'";
    let params = [];

    // Check for property_type query parameter and add filter if present
    if (req.query.property_type && req.query.property_type !== 'all') {
        query += " AND `property-type` = ?";
        params.push(req.query.property_type);
    }

    connection.query(query, params, (err, card) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).send('Server error: Unable to fetch properties.');
        } else {
            // Render the template with filtered data
            res.render('customer-buy-page', {
                card: card  // 'card' is your array of properties
            });
        }
    });
});


newapp2.get('/costumer-sell-page.html', (req, res) => {
    let query = "SELECT  * FROM all_properties where rentSell = 'Rent'";
    let params = [];

    // Check for property_type query parameter and add filter if present
    if (req.query.property_type && req.query.property_type !== 'all') {
        query += " AND `property-type` = ?";
        params.push(req.query.property_type);
    }

    connection.query(query, params, (err, card) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).send('Server error: Unable to fetch properties.');
        } else {
            // Render the template with filtered data
            res.render('costumer-sell-page', {
                card: card  // 'card' is your array of properties
            });
        }
    });
});

newapp2.get('/customer-rent-page.html', (req, res) => {
    let query = "SELECT * FROM all_properties WHERE rentSell = 'Rent'";
    let params = [];

    // Check for property_type query parameter and add filter if present
    if (req.query.property_type && req.query.property_type !== 'all') {
        query += " AND `property-type` = ?";
        params.push(req.query.property_type);
    }

    connection.query(query, params, (err, card) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).send('Server error: Unable to fetch properties.');
        } else {
            // Render the template with filtered data
            res.render('customer-rent-page', {
                card: card  // 'card' is your array of properties
            });
        }
    });
});


// propert details

newapp2.get('/property-detail', (req, res) => {
  const propertyId = req.query.id;
  if (!propertyId) return res.status(400).send('Property ID is required.');

  if (!req.user) return res.redirect('/login');

  // First, get user role from signin table
  connection.query("SELECT role FROM signin WHERE id = ?", [req.user.id], (err, userResults) => {
    if (err) return res.status(500).send('Database query error.');
    if (userResults.length === 0) return res.status(404).send('User not found.');

    const isAdmin = userResults[0].role === 'admin';

    // Function to fetch property from a table
    const fetchProperty = (tableName, callback) => {
      connection.query(`SELECT * FROM ${tableName} WHERE id = ?`, [propertyId], (err, results) => {
        if (err) return callback(err, null);
        callback(null, results.length > 0 ? results[0] : null);
      });
    };

    // Try all_properties first
    fetchProperty('all_properties', (err, property) => {
      if (err) return res.status(500).send('Database query error.');
      
      if (property) {
        // Property found in all_properties
        console.log('Property found in all_properties:', property.id, 'agentId:', property.agentId);
        fetchAgentAndRender(property);
      } else {
        // Try sold_properties
        fetchProperty('sold_properties', (err2, property2) => {
          if (err2) return res.status(500).send('Database query error.');
          
          if (property2) {
            // Property found in sold_properties
            console.log('Property found in sold_properties:', property2.id, 'agentId:', property2.agentId);
            fetchAgentAndRender(property2);
          } else {
            return res.status(404).send('No property found with that ID.');
          }
        });
      }
    });

    function fetchAgentAndRender(property) {
      // Then, get agent details using agentId from property
      if (property.agentId) {
        console.log('Fetching agent for agentId:', property.agentId);
        connection.query("SELECT * FROM signin WHERE id = ? AND role = 'agent'", [property.agentId], (err3, agentResults) => {
          if (err3) {
            console.error('Agent query error:', err3);
            return res.status(500).send('Database query error.');
          }
          
          console.log('Agent query results:', agentResults.length);
          const agent = agentResults.length > 0 ? agentResults[0] : null;

          res.render('view-details', {
            property: property,
            isAdmin,
            userId: req.user.id,
            userEmail: req.user.email,
            agent: agent  // Agent details from signin table
          });
        });
      } else {
        console.log('No agentId for property:', property.id);
        // No agentId, render without agent details
        res.render('view-details', {
          property: property,
          isAdmin,
          userId: req.user.id,
          userEmail: req.user.email,
          agent: null
        });
      }
    }
  });
});


//contact form

newapp2.post('/contact', ensureAuthenticated, (req, res) => {
    const { name, email, phone, subject, message } = req.body;
    
    // Basic validation
    if (!name || !email || !phone || !message) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
    }
    
    // Email options (customize 'to' with your actual admin email)
    const mailOptions = {
        from: `"IBA Real Estate" <noreply@ibarealestate.com>`,  // Use a verified sender (not user's email for spam reasons)
        to: 'admin@ibarealestate.com',  // Replace with your admin email
        subject: `Contact Form: ${subject || 'New Inquiry'}`,
        html: `
            <h2>New Contact Message from IBA REAL ESTATE Website</h2>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Phone:</strong> ${phone}</p>
            <p><strong>Subject:</strong> ${subject || 'N/A'}</p>
            <p><strong>Message:</strong></p>
            <p>${message.replace(/\n/g, '<br>')}</p>  <!-- Preserve line breaks -->
            <hr>
            <p><em>This message was submitted on ${new Date().toLocaleString()}.</em></p>
            <p>Best regards,<br>IBA Real Estate Contact Form</p>
        `
    };
    
    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Email send error:', error);
            return res.status(500).json({ success: false, message: 'Failed to send email. Please try again later.' });
        } 
        
        console.log('Contact email sent successfully:', info.response);
        return res.status(200).json({ success: true, message: 'Your message has been sent successfully! We\'ll get back to you soon.' });
    });
});

newapp2.get('/property-detail.html', (req, res) => {
    res.render('login');
});


newapp2.post('/detail-contact', ensureAuthenticated, (req, res) => {
  const { name, email, phone, message, propertyId } = req.body;
  const userId = req.user.id;  // Sender's ID

  // Basic validation
  if (!name || !email || !phone || !message || !propertyId) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ success: false, message: 'Please enter a valid email address' });
  }

  // First, fetch the property to get agentId
  connection.query("SELECT agentId FROM all_properties WHERE id = ?", [propertyId], (err, propResults) => {
    if (err) {
      console.error('Property fetch error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    if (propResults.length === 0) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }

    const agentId = propResults[0].agentId;
    let receiverId = null;  // Will be set to agent or admin
    let recipientEmail = 'ibarealestate2023@gmail.com';  // Default to admin

    if (agentId) {
      // Fetch agent details
      connection.query("SELECT email FROM signin WHERE id = ? AND role = 'agent'", [agentId], (err2, agentResults) => {
        if (err2) {
          console.error('Agent fetch error:', err2);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (agentResults.length > 0 && agentResults[0].email) {
          recipientEmail = agentResults[0].email;
          receiverId = agentId;
        } else {
          // Agent not found or no email, use admin
          receiverId = null;  // Will fetch admin ID below
        }

        sendEmailAndSave();
      });
    } else {
      // No agentId, use admin
      sendEmailAndSave();
    }

    function sendEmailAndSave() {
      if (!receiverId) {
        // Fetch admin ID
        connection.query("SELECT id FROM signin WHERE email = 'ibarealestate2023@gmail.com' AND role = 'admin'", (err3, adminResults) => {
          if (err3 || adminResults.length === 0) {
            console.error('Admin not found:', err3);
            return res.status(500).json({ success: false, message: 'Admin not found' });
          }
          receiverId = adminResults[0].id;
          proceedWithEmail();
        });
      } else {
        proceedWithEmail();
      }
    }

    function proceedWithEmail() {
      // Send email to agent or admin
      const mailOptions = {
        from: `"IBA Real Estate" <noreply@ibarealestate.com>`,
        to: recipientEmail,
        subject: 'New Contact Message from Property Detail Page',
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

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Email send error:', error);
          return res.status(500).json({ success: false, message: 'Failed to send email. Please try again later.' });
        }

        console.log('Email sent successfully to:', recipientEmail);

        // Save message to chat database
        connection.query(
          'INSERT INTO chat_messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
          [userId, receiverId, message],
          (insertErr, insertResult) => {
            if (insertErr) {
              console.error('Error saving to chat:', insertErr);
              return res.status(500).json({ success: false, message: 'Message sent via email, but chat save failed.' });
            }

            // Redirect to chat page after success with success message
            res.redirect('/chat?success=Message sent! Redirecting to chat...');
          }
        );
      });
    }
  });
});

newapp2.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error('Logout error:', err);
        res.clearCookie('connect.sid');  // Clear session cookie
        res.redirect('/');  // Or '/customer-buy-page.html'
    });
});

// Optional: POST for AJAX logout (used in JS confirm)
newapp2.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true, message: 'Logged out successfully' });
    });
});


//property sold
newapp2.get('/sold', ensureAuthenticated, (req, res) => {  // Add auth if needed
    const propertyId = req.query.id;  // From URL: /sold?id=123
    
    // Validation
    if (!propertyId || isNaN(propertyId)) {
        return res.redirect('/sell-page.html?error=Invalid property ID. Please try again.');  // Early return
    }
    
    console.log(`Marking property ID ${propertyId} as sold...`);
    
    // Step 1: Fetch from all_properties
    connection.query(
        'SELECT * FROM all_properties WHERE id = ?',
        [propertyId],
        (err, results) => {
            if (err) {
                console.error('DB fetch error:', err);
                return res.redirect('/sell-page.html?error=Database error. Please contact support.');  // Early return
            }
            
            if (results.length === 0) {
                return res.redirect('/sell-page.html?error=Property not found.');  // Early return
            }
            
            const property = results[0];
            console.log('Fetched property:', property.title);
            
            // Step 2: Insert into sold_properties
            const insertQuery = `
                INSERT INTO sold_properties (
                    ownerName, ownerEmail, ownerPhone, propertyAddress, 
                    bedrooms, bathrooms, description, sqft, 
                    image_data, video, amount, title, rentSell, agentId, \`property-type\`
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            
            
            const insertValues = [
                property.ownerName || '',
                property.ownerEmail || '',
                property.ownerPhone || '',
                property.propertyAddress || '',
                property.bedrooms || '0',
                property.bathrooms || '0',
                property.description || '',
                property.sqft || '0',
                property.image_data,  // LONGBLOB
                property.video,       // LONGBLOB
                property.amount || null,
                property.title || null,
                property.rentSell || null,
                property.agentId, 
                property['property-type'] || null
            ];
            
            connection.query(insertQuery, insertValues, (insertErr, insertResult) => {
                if (insertErr) {
                    console.error('DB insert error:', insertErr);
                    return res.redirect('/sell-page.html?error=Failed to mark property as sold. Please try again.');  // Early return
                }
                
                console.log('Inserted into sold_properties with ID:', insertResult.insertId);
                
                // Step 3: Delete from all_properties (now with single redirect inside callback)
                connection.query(
                    'DELETE FROM all_properties WHERE id = ?',
                    [propertyId],
                    (deleteErr) => {
                        if (deleteErr) {
                            console.error('DB delete error (non-critical):', deleteErr);
                            // Still succeed - insert worked; just log delete failure
                        } else {
                            console.log('Deleted from all_properties');
                        }
                        
                        // SINGLE REDIRECT: After delete (success or error) - with title for frontend
                        res.redirect(`/index.html?success=sold&title=${encodeURIComponent(property.title)}`);
                        return;  // Ensure no further execution
                    }
                );
            });
        }
    );
});


// Route 1: View All Sold Properties (GET /sold-properties)
newapp2.get('/sold-properties', ensureAuthenticated, (req, res) => {
  

    connection.query('SELECT * FROM sold_properties ORDER BY id DESC', (err, results) => {  // DESC for newest first
        if (err) {
            console.error('DB fetch sold properties error:', err);
            return res.redirect('/sold-properties?error=Failed to load sold properties.');
        }

        res.render('sold-properties', { 
            soldProperties: results,  // Array of properties
            isAdmin: true 
        });
    });
});

// Route 2: Edit Form (GET /edit-sold?id=123)
newapp2.get('/edit-sold', ensureAuthenticated, (req, res) => {
    /*if (!req.user || req.user.role !== 'admin') {
        return res.redirect('/sold-properties?error=Unauthorized access. Admins only.');
    }*/

    const propertyId = req.query.id;
    if (!propertyId || isNaN(propertyId)) {
        return res.redirect('/sold-properties?error=Invalid property ID.');
    }

    connection.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId], (err, results) => {
        if (err) {
            console.error('DB fetch for edit error:', err);
            return res.redirect('/login');
        }

        if (results.length === 0) {
            return res.redirect('/sold-properties?error=Property not found.');
        }

        res.render('edit-sold', { 
            property: results[0], 
            isAdmin: true 
        });
    });
});

// Route 3: Update Sold Property (POST /update-sold)
newapp2.post('/update-sold', ensureAuthenticated, (req, res) => {
   /* if (!req.user || req.user.role !== 'admin') {
        return res.redirect('/sold-properties?error=Unauthorized access. Admins only.');
    }*/

    const propertyId = req.body.id;
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
        'property-type': req.body['property-type'] || null
        // Note: image_data and video not updated here (no upload); extend if needed
    };

    const updateQuery = `
        UPDATE sold_properties 
        SET title = ?, description = ?, amount = ?, propertyAddress = ?, 
            bedrooms = ?, bathrooms = ?, sqft = ?, ownerName = ?, 
            ownerEmail = ?, ownerPhone = ?, rentSell = ?, \`property-type\` = ? 
        WHERE id = ?
    `;

    const updateValues = [
        updates.title, updates.description, updates.amount, updates.propertyAddress,
        updates.bedrooms, updates.bathrooms, updates.sqft, updates.ownerName,
        updates.ownerEmail, updates.ownerPhone, updates.rentSell, updates['property-type'],
        propertyId
    ];

    connection.query(updateQuery, updateValues, (updateErr) => {
        if (updateErr) {
            console.error('DB update error:', updateErr);
            return res.redirect('/sold-properties?error=Failed to update property.');
        }

        console.log(`Updated sold property ID ${propertyId}`);
        res.redirect('/sold-properties?success=Property updated successfully!');
    });
});

// Route 4: Move Back to Sell (Unsold) - POST /unsold
newapp2.post('/unsold', ensureAuthenticated, (req, res) => {
   /* if (!req.user || req.user.role !== 'admin') {
        return res.redirect('/sold-properties?error=Unauthorized access. Admins only.');
    }*/

    const propertyId = req.body.id;
    if (!propertyId || isNaN(propertyId)) {
        return res.redirect('/sold-properties?error=Invalid property ID.');
    }

    // Step 1: Fetch from sold_properties
    connection.query('SELECT * FROM sold_properties WHERE id = ?', [propertyId], (err, results) => {
        if (err) {
            console.error('DB fetch for unsold error:', err);
            return res.redirect('/sold-properties?error=Database error.');
        }

        if (results.length === 0) {
            return res.redirect('/sold-properties?error=Property not found.');
        }

        const property = results[0];
        console.log('Fetching sold property for unsold:', property.title);

        // Step 2: Insert into all_properties (copy fields)
        const insertQuery = `
            INSERT INTO all_properties (
                ownerName, ownerEmail, ownerPhone, propertyAddress, 
                bedrooms, bathrooms, description, sqft, 
                image_data, video, amount, title, rentSell, \`property-type\`, agentId
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const insertValues = [
            property.ownerName || '',
            property.ownerEmail || '',
            property.ownerPhone || '',
            property.propertyAddress || '',
            property.bedrooms || '0',
            property.bathrooms || '0',
            property.description || '',
            property.sqft || '0',
            property.image_data,
            property.video,
            property.amount || null,
            property.title || null,
            property.rentSell || null,
            property['property-type'] || null,
            property.agentId
        ];

        connection.query(insertQuery, insertValues, (insertErr, insertResult) => {
            if (insertErr) {
                console.error('DB insert to all_properties error:', insertErr);
                return res.redirect('/sold-properties?error=Failed to move property back to sales.');
            }

            console.log('Inserted to all_properties with ID:', insertResult.insertId);

            // Step 3: Delete from sold_properties
            connection.query('DELETE FROM sold_properties WHERE id = ?', [propertyId], (deleteErr) => {
                if (deleteErr) {
                    console.error('DB delete from sold_properties error:', deleteErr);
                    return res.redirect('/sold-properties?error=Failed to remove from sold list.');
                }

                console.log('Moved back to all_properties - deleted from sold_properties');
                res.redirect('/sold-properties?success=Property moved back to active sales!');
            });
        });
    });
});

// Route 5: Delete Sold Property (POST /delete-sold)
newapp2.post('/delete-sold', ensureAuthenticated, (req, res) => {
   /* if (!req.user || req.user.role !== 'admin') {
        return res.redirect('/sold-properties?error=Unauthorized access. Admins only.');
    }*/

    const propertyId = req.body.id;
    if (!propertyId || isNaN(propertyId)) {
        return res.redirect('/sold-properties?error=Invalid property ID.');
    }

    connection.query('DELETE FROM sold_properties WHERE id = ?', [propertyId], (deleteErr, result) => {
        if (deleteErr) {
            console.error('DB delete error:', deleteErr);
            return res.redirect('/sold-properties?error=Failed to delete property.');
        }

        if (result.affectedRows === 0) {
            return res.redirect('/sold-properties?error=Property not found.');
        }

        console.log(`Deleted sold property ID ${propertyId}`);
        res.redirect('/sold-properties?success=Property deleted successfully!');
    });
});


//manaage agent



// GET /manage/agent - Display manage agent page with stats
newapp2.get('/manage-agent', (req, res) => {
  // Query to get agents with property stats aggregated from all tables
  const query = `
    SELECT 
      s.id, s.firstName, s.middleName, s.lastName, s.email, s.phone,
      COALESCE(stats.propertiesAdded, 0) AS propertiesAdded,
      COALESCE(stats.soldProperties, 0) AS soldProperties,
      COALESCE(stats.pendingProperties, 0) AS pendingProperties
    FROM signin s
    LEFT JOIN (
      SELECT 
        agentId,
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
  `;
  
  connection.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Server error');
    }
    res.render('manage-agent', { agents: results, isAdmin: true });
  });
});

// POST /manage/agent - Add new agent
newapp2.post('/manage/agent', (req, res) => {
  const { firstName, middleName, lastName, email, phone } = req.body;

  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  const checkEmailQuery = 'SELECT COUNT(*) AS count FROM signin WHERE email = ?';
  connection.query(checkEmailQuery, [email], (err, results) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (results[0].count > 0) return res.status(400).json({ error: 'Email already exists' });

    const tempPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = bcrypt.hashSync(tempPassword, 10);

    const insertQuery = 'INSERT INTO signin (firstName, middleName, lastName, email, phone, confirmPassword, role) VALUES (?, ?, ?, ?, ?, ?, ?)';
    connection.query(insertQuery, [firstName, middleName || null, lastName, email, phone || null, hashedPassword, 'agent'], (err, result) => {
      if (err) return res.status(500).json({ error: 'Server error' });

      // Send welcome email
      const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Welcome to Iba Real Estate - Agent Account Created',
        html: `
          <h1>Welcome to Iba Real Estate!</h1>
          <p>Dear ${firstName} ${lastName},</p>
          <p>Your agent account has been created. Login details:</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Temporary Password:</strong> ${tempPassword}</p>
          <p>Please change your password after logging in.</p>
          <p>Best regards,<br>The Iba Real Estate Team</p>
        `
      };

      transporter.sendMail(mailOptions, (error) => {
        if (error) console.error('Email error:', error);
        // Return JSON success response to trigger popup
        res.json({ success: true, message: 'Agent added successfully! Email sent with login details.' });
      });
    });
  });
});

// PUT /manage/agent/:id - Update agent
newapp2.put('/manage/agent/:id', (req, res) => {
  const { id } = req.params;
  const { firstName, middleName, lastName, email, phone } = req.body;

  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email address');
  }

  const updateQuery = 'UPDATE signin SET firstName = ?, middleName = ?, lastName = ?, email = ?, phone = ? WHERE id = ? AND role = "agent"';
  connection.query(updateQuery, [firstName, middleName || null, lastName, email, phone || null, id], (err) => {
    if (err) return res.status(500).send('Server error');
    res.send('Agent updated successfully');
  });
});

// DELETE /manage/agent/:id - Delete agent
newapp2.delete('/manage/agent/:id', (req, res) => {
  const { id } = req.params;

  // Optional: Handle properties (e.g., reassign or delete)
  const deleteQuery = 'DELETE FROM signin WHERE id = ? AND role = "agent"';
  connection.query(deleteQuery, [id], (err) => {
    if (err) return res.status(500).send('Server error');
    res.send('Agent deleted successfully');
  });
});

// Additional routes for property management (if needed for agents)
newapp2.post('/properties/approve/:id', (req, res) => {
  const { id } = req.params;
  // Move from sales_approval to all_properties
  const selectQuery = 'SELECT * FROM sales_approval WHERE id = ?';
  connection.query(selectQuery, [id], (err, results) => {
    if (err || results.length === 0) return res.status(500).send('Error');
    const property = results[0];
    const insertQuery = 'INSERT INTO all_properties (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description, sqft, image_data, video, amount, title, rentSell, `property-type`, agentId, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
    connection.query(insertQuery, [property.ownerName, property.ownerEmail, property.ownerPhone, property.propertyAddress, property.bedrooms, property.bathrooms, property.description, property.sqft, property.image_data, property.video, property.amount, property.title, property.rentSell, property.property_type, property.agentId, 'approved'], (err) => {
      if (err) return res.status(500).send('Error');
      connection.query('DELETE FROM sales_approval WHERE id = ?', [id]);
      res.send('Property approved');
    });
  });
});

newapp2.post('/properties/sell/:id', (req, res) => {
  const { id } = req.params;
  // Move from all_properties to sold_properties
  const selectQuery = 'SELECT * FROM all_properties WHERE id = ?';
  connection.query(selectQuery, [id], (err, results) => {
    if (err || results.length === 0) return res.status(500).send('Error');
    const property = results[0];
    const insertQuery = 'INSERT INTO sold_properties (ownerName, ownerEmail, ownerPhone, propertyAddress, bedrooms, bathrooms, description, sqft, image_data, video, amount, title, rentSell, `property-type`, agentId, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
    connection.query(insertQuery, [property.ownerName, property.ownerEmail, property.ownerPhone, property.propertyAddress, property.bedrooms, property.bathrooms, property.description, property.sqft, property.image_data, property.video, property.amount, property.title, property.rentSell, property['property-type'], property.agentId, 'sold'], (err) => {
      if (err) return res.status(500).send('Error');
      connection.query('DELETE FROM all_properties WHERE id = ?', [id]);
      res.send('Property marked as sold');
    });
  });
});



// Get Listings
// Assuming you have Express app, MySQL connection, and session middleware set up
// Example: const app = express(); const db = mysql.createConnection({...}); app.use(session({...}));



// Assuming you have Express app, MySQL connection, and session middleware set up
// Example: const newapp2 = express(); const connection = mysql.createConnection({...}); newapp2.use(session({...}));

// Middleware to check if agent is logged in


// Corrected route for rendering agent dashboard (assuming '/submit-listing' is a typo or specific route; adjust as needed)
newapp2.get('/submit-listing', (req, res) => {
  const agentId = req.session.id; // Use session.id as agentId
  const queries = [
    // Total Properties (count from all_properties and sold_properties, excluding sales_approval as it's pending)
    `SELECT COUNT(*) AS totalProperties FROM (
      SELECT id FROM all_properties WHERE agentId = ?
      UNION
      SELECT id FROM sold_properties WHERE agentId = ?
    ) AS combined`,
    // Total Agents (count all agents)
    `SELECT COUNT(*) AS totalAgents FROM signin WHERE role = 'agent'`,
    // Pending Approvals (from sales_approval where status = 'pending')
    `SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`,
    // Sold Properties (from sold_properties)
    `SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`,
    // Recent Activities (from all_properties, ordered by created_at)
    `SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`,
    // Agents (agent's own data)
    `SELECT id, firstName, lastName, email, phone FROM signin WHERE id = ?`,
    // Approvals (agent's pending properties from sales_approval)
    `SELECT s.id, s.title, s.status, u.firstName AS agentName FROM sales_approval s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ? AND s.status = 'pending'`,
    // Customers (from signin where role = 'user', limit for display)
    `SELECT firstName, lastName, email, phone, role FROM signin WHERE role = 'user' LIMIT 10`,
    // Sold Props (from sold_properties)
    `SELECT s.title, u.firstName AS agentName, s.amount, s.created_at AS soldDate FROM sold_properties s JOIN signin u ON s.agentId = u.id WHERE s.agentId = ?`,
    // Settings (placeholder, can be from a settings table or hardcoded)
    `SELECT 'IBA Real Estate' AS siteTitle, 'admin@example.com' AS adminEmail`
  ];

  const queryPromises = queries.map((query, index) => {
    return new Promise((resolve, reject) => {
      let params = [];
      switch (index) {
        case 0: // totalProperties
          params = [agentId, agentId];
          break;
        case 1: // totalAgents
          params = [];
          break;
        case 2: // pendingApprovals
          params = [agentId];
          break;
        case 3: // soldProperties
          params = [agentId];
          break;
        case 4: // activities
          params = [agentId];
          break;
        case 5: // agents
          params = [agentId];
          break;
        case 6: // approvals
          params = [agentId];
          break;
        case 7: // customers
          params = [];
          break;
        case 8: // soldProps
          params = [agentId];
          break;
        case 9: // settings
          params = [];
          break;
      }
      connection.query(query, params, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
  });

  Promise.all(queryPromises).then((results) => {
    const data = {
      totalProperties: results[0][0].totalProperties,
      totalAgents: results[1][0].totalAgents,
      pendingApprovals: results[2][0].pendingApprovals,
      soldProperties: results[3][0].soldProperties,
      activities: results[4],
      agents: results[5],
      approvals: results[6],
      customers: results[7],
      soldProps: results[8],
      siteTitle: results[9][0].siteTitle,
      adminEmail: results[9][0].adminEmail,
      username: req.session.firstName, // Assuming session stores firstName
      surname: req.session.lastName, // Assuming session stores lastName
      isAdmin: req.session.role === 'admin', // Correct boolean check
      isAgent: req.session.role === 'agent' // Correct boolean check
    };
    return res.render('agent-dashboard', data);
  }).catch((err) => {
    console.error('Data fetch error:', err);
    return res.status(500).send('Server error');
  });
});



// Assuming you have Express app, MySQL connection, and session middleware set up
// Example: const newapp2 = express(); const connection = mysql.createConnection({...}); newapp2.use(session({...}));



// Route to render the Manage Listings page
// Route to render the Manage Listings page with data from database
// Assuming you have Express app, MySQL connection, and session middleware set up
// Example: const newapp2 = express(); const connection = mysql.createConnection({...}); newapp2.use(session({...}));

// Middleware to check if agent is logged in
function requireAgent(req, res, next) {
  if (req.session && req.session.role === 'agent' && req.session.userId) { // Check userId (numeric ID)
    next();
  } else {
    console.log('Unauthorized access attempt:', req.session);
    res.status(401).json({ error: 'Unauthorized: Please log in as an agent' });
  }
}

// Route to render the Manage Listings page with data from database
newapp2.get('/manage-listings', ensureAuthenticated, (req, res) => {
  const agentId = req.user.id; // Use userId (numeric ID from login)
  console.log('Rendering manage-listings for agentId:', agentId);

  if (!agentId) {
    console.error('AgentId is missing in session');
    return res.status(400).send('Invalid session: Agent ID not found');
  }

  // Queries to fetch listings
  const queries = [
    // Pending listings from sales_approval
    `SELECT id, title, status FROM sales_approval WHERE agentId = ? AND status = 'pending'`,
    // Approved listings from all_properties
    `SELECT id, title, status FROM all_properties WHERE agentId = ? AND status = 'approved'`,
    // Sold listings from sold_properties
    `SELECT id, title, status FROM sold_properties WHERE agentId = ?`,
    // All listings (union of all_properties and sold_properties)
    `(SELECT id, title, status FROM all_properties WHERE agentId = ?) UNION (SELECT id, title, status FROM sold_properties WHERE agentId = ?)`
  ];

  const queryPromises = queries.map((query, index) => {
    return new Promise((resolve, reject) => {
      // For the union query, pass agentId twice
      const params = index === 3 ? [agentId, agentId] : [agentId];
      connection.query(query, params, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
  });

  Promise.all(queryPromises).then((results) => {
    const data = {
      title: 'Manage Listings',
      pendingListings: results[0], // Array of pending listings
      approvedListings: results[1], // Array of approved listings
      soldListings: results[2], // Array of sold listings
      allListings: results[3] // Array of all listings
    };
    console.log('Data passed to EJS:', {
      pendingCount: results[0].length,
      approvedCount: results[1].length,
      soldCount: results[2].length,
      allCount: results[3].length,
      agentId: agentId
    });
    res.render('manage-listing', data); // Render the EJS file with data
  }).catch((err) => {
    console.error('Data fetch error for manage-listings:', err);
    res.status(500).send('Server error');
  });
});

// Route for all listings (from all_properties table)
newapp2.get('/agent/listings/all', (req, res) => {
  const agentId = req.session.id;
  console.log('Fetching all listings for agentId:', agentId); // Debug log

  if (!agentId) {
    console.error('AgentId is missing in session');
    return res.status(400).json({ error: 'Invalid session: Agent ID not found' });
  }

  const query = 'SELECT id, title, status FROM all_properties WHERE agentId = ?';
  connection.query(query, [agentId], (err, results) => {
    if (err) {
      console.error('Database error fetching all listings:', err);
      return res.status(500).json({ error: 'Database error: ' + err.message });
    }
    console.log('All listings fetched:', results.length, 'items'); // Debug log
    res.json(results);
  });
});


// Route for pending listings (from sales_approval table)
newapp2.get('/agent/listings/pending',  (req, res) => {
  const agentId = req.session.id;
  console.log('Fetching pending listings for agentId:', agentId); // Debug log

  if (!agentId) {
    console.error('AgentId is undefined in session');
    return res.status(400).json({ error: 'Invalid session: Agent ID not found' });
  }

  const query = 'SELECT id, title, status FROM sales_approval WHERE agentId = ? AND status = "pending"';
  connection.query(query, [agentId], (err, results) => {
    if (err) {
      console.error('Database error fetching pending listings:', err);
      return res.status(500).json({ error: 'Database error: ' + err.message });
    }
    console.log('Pending listings fetched:', results.length, 'items'); // Debug log
    res.json(results);
  });
});

// Route for approved listings (from all_properties table)
newapp2.get('/agent/listings/approved',  (req, res) => {
  const agentId = req.session.id;
  console.log('Fetching approved listings for agentId:', agentId); // Debug log

  if (!agentId) {
    console.error('AgentId is undefined in session');
    return res.status(400).json({ error: 'Invalid session: Agent ID not found' });
  }

  const query = 'SELECT id, title, status FROM all_properties WHERE agentId = ? AND status = "approved"';
  connection.query(query, [agentId], (err, results) => {
    if (err) {
      console.error('Database error fetching approved listings:', err);
      return res.status(500).json({ error: 'Database error: ' + err.message });
    }
    console.log('Approved listings fetched:', results.length, 'items'); // Debug log
    res.json(results);
  });
});

// Route for sold listings (from sold_properties table)
newapp2.get('/agent/listings/sold',  (req, res) => {
  const agentId = req.session.id;
  console.log('Fetching sold listings for agentId:', agentId); // Debug log

  if (!agentId) {
    console.error('AgentId is undefined in session');
    return res.status(400).json({ error: 'Invalid session: Agent ID not found' });
  }

  const query = 'SELECT id, title, status FROM sold_properties WHERE agentId = ?';
  connection.query(query, [agentId], (err, results) => {
    if (err) {
      console.error('Database error fetching sold listings:', err);
      return res.status(500).json({ error: 'Database error: ' + err.message });
    }
    console.log('Sold listings fetched:', results.length, 'items'); // Debug log
    res.json(results);
  });
});

newapp2.get('/edit-property/:id', requireAgent, (req, res) => {
  const propertyId = req.params.id;
  const agentId = req.session.userId;

  // Query to find the property in any table (pending, approved, sold)
  const queries = [
    `SELECT *, 'pending' AS tableName FROM sales_approval WHERE id = ? AND agentId = ?`,
    `SELECT *, 'approved' AS tableName FROM all_properties WHERE id = ? AND agentId = ?`,
    `SELECT *, 'sold' AS tableName FROM sold_properties WHERE id = ? AND agentId = ?`
  ];

  const queryPromises = queries.map(query => {
    return new Promise((resolve, reject) => {
      connection.query(query, [propertyId, agentId], (err, results) => {
        if (err) reject(err);
        else resolve(results[0] || null); // Return the first match or null
      });
    });
  });

  Promise.all(queryPromises).then(results => {
    const property = results.find(r => r !== null); // Find the property in one of the tables
    if (!property) {
      return res.status(404).json({ error: 'Property not found or not owned by you' });
    }
    res.json(property); // Return property data as JSON
  }).catch(err => {
    console.error('Error fetching property for edit:', err);
    res.status(500).json({ error: 'Database error' });
  });
});

// Route to update property (POST)
newapp2.post('/update-property/:id', (req, res) => {
  const propertyId = req.params.id;
  const agentId = req.session.userId;
  const { title, description, amount, rentSell, property_type, status, bedrooms, bathrooms } = req.body;

  console.log('Update request for propertyId:', propertyId, 'by agentId:', agentId); // Debug log
  console.log('Update data:', { title, description, amount, rentSell, property_type, status, bedrooms, bathrooms }); // Debug log

  // First, find which table the property is in
  const findQuery = `
    SELECT 'pending' AS tableName FROM sales_approval WHERE id = ? AND agentId = ?
    UNION
    SELECT 'approved' AS tableName FROM all_properties WHERE id = ? AND agentId = ?
    UNION
    SELECT 'sold' AS tableName FROM sold_properties WHERE id = ? AND agentId = ?
  `;

  connection.query(findQuery, [propertyId, agentId, propertyId, agentId, propertyId, agentId], (err, results) => {
    if (err) {
      console.error('Error finding property table:', err);
      return res.status(500).json({ error: 'Database error finding table: ' + err.message });
    }
    if (results.length === 0) {
      console.error('Property not found for update:', propertyId, 'agentId:', agentId);
      return res.status(404).json({ error: 'Property not found or not owned by you' });
    }

    const tableName = results[0].tableName;
    console.log('Property found in table:', tableName); // Debug log

    let table, propertyTypeColumn;
    if (tableName === 'pending') {
      table = 'sales_approval';
      propertyTypeColumn = 'property_type';
    } else if (tableName === 'approved') {
      table = 'all_properties';
      propertyTypeColumn = '`property-type`'; // Backticks for special chars
    } else if (tableName === 'sold') {
      table = 'sold_properties';
      propertyTypeColumn = '`property-type`';
    }

    // Update the property
    const updateQuery = `UPDATE ${table} SET title = ?, description = ?, amount = ?, rentSell = ?, ${propertyTypeColumn} = ?, status = ?, bedrooms = ?, bathrooms = ? WHERE id = ? AND agentId = ?`;
    console.log('Update query:', updateQuery); // Debug log
    console.log('Update params:', [title, description, amount, rentSell, property_type, status, bedrooms, bathrooms, propertyId, agentId]); // Debug log

    connection.query(updateQuery, [title, description, amount, rentSell, property_type, status, bedrooms, bathrooms, propertyId, agentId], (err, result) => {
      if (err) {
        console.error('Error updating property:', err);
        return res.status(500).json({ error: 'Update failed: ' + err.message });
      }
      console.log('Property updated successfully:', result.affectedRows, 'rows affected');
      res.json({ success: true, message: 'Property updated successfully' });
    });
  });
});


// Assuming you have Express app, MySQL connection, and session middleware set up
// Example: const newapp2 = express(); const connection = mysql.createConnection({...}); newapp2.use(session({...}));

// Middleware to check if agent is logged in


// Route to render Track Performance page with data
newapp2.get('/track-performance', (req, res) => {
  const agentId = req.session.userId;

  // Sample performance data (replace with real queries if you have a performance table)
  // E.g., SELECT month, views, inquiries FROM performance WHERE agentId = ? ORDER BY month
  const chartData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'], // Months
    views: [1200, 1500, 1800, 2200, 2500, 2800], // Sample views
    inquiries: [100, 150, 200, 250, 300, 350] // Sample inquiries
  };

  // Fetch stats (reuse from your dashboard logic)
  const queries = [
    `SELECT COUNT(*) AS totalProperties FROM (
      SELECT id FROM all_properties WHERE agentId = ?
      UNION
      SELECT id FROM sold_properties WHERE agentId = ?
    ) AS combined`,
    `SELECT COUNT(*) AS pendingApprovals FROM sales_approval WHERE agentId = ? AND status = 'pending'`,
    `SELECT COUNT(*) AS soldProperties FROM sold_properties WHERE agentId = ?`,
    `SELECT CONCAT('Property: ', title) AS description, created_at AS date FROM all_properties WHERE agentId = ? ORDER BY created_at DESC LIMIT 5`
  ];

  const queryPromises = queries.map((query, index) => {
    return new Promise((resolve, reject) => {
      const params = index === 0 ? [agentId, agentId] : [agentId];
      connection.query(query, params, (err, results) => {
        if (err) reject(err);
        else resolve(results);
      });
    });
  });

  Promise.all(queryPromises).then((results) => {
    const data = {
      title: 'Track Performance',
      totalProperties: results[0][0].totalProperties,
      pendingApprovals: results[1][0].pendingApprovals,
      soldProperties: results[2][0].soldProperties,
      activities: results[3],
      chartData: chartData // Pass chart data to EJS
    };
    res.render('track-performance', data);
  }).catch((err) => {
    console.error('Data fetch error for track-performance:', err);
    res.status(500).send('Server error');
  });
});


// Chat Routes (UPDATED for signin table and your session setup)
newapp2.get('/chat', ensureAuthenticated, (req, res) => {
  const userId = req.user.id;
  const successMessage = req.query.success;
  const receiverId = req.query.receiverId;

  if (receiverId) {
    // Existing chat logic
    connection.query("SELECT firstName, lastName, role FROM signin WHERE id = ?", [receiverId], (err, receiverResults) => {
      let receiverName = 'Unknown';
      let isAgent = false;

      if (!err && receiverResults.length > 0) {
        const receiver = receiverResults[0];
        receiverName = `${receiver.firstName || ''} ${receiver.lastName || ''}`.trim();
        if (!receiverName) receiverName = receiver.role === 'admin' ? 'Admin' : 'Unknown';
        isAgent = receiver.role === 'agent';
      }

      connection.query(
        'SELECT * FROM chat_messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC',
        [userId, receiverId, receiverId, userId],
        (err, messages) => {
          if (err) return res.status(500).send('Error loading chat');
          res.render('chat', { messages, userId, receiverId, success: successMessage, receiverName, isAgent, chatList: null });
        }
      );
    });
  } else {
    // Fetch chat list (fixed to include all chats where user is sender or receiver)
    connection.query(
      `SELECT DISTINCT 
         CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AS receiverId,
         s.firstName, s.lastName, s.role,
         (SELECT message FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessage,
         (SELECT timestamp FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessageTime
       FROM chat_messages cm
       JOIN signin s ON s.id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END
       WHERE cm.sender_id = ? OR cm.receiver_id = ?
       ORDER BY lastMessageTime DESC`,
      [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId],
      (err, chatList) => {
        if (err) {
          console.error('Chat list query error:', err);
          return res.status(500).send('Error loading chats');
        }
        const processedChatList = chatList.map(chat => ({
          receiverId: chat.receiverId,
          receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || (chat.role === 'admin' ? 'Admin' : 'Unknown'),
          isAgent: chat.role === 'agent',
          lastMessage: chat.lastMessage,
          lastMessageTime: chat.lastMessageTime
        }));
        res.render('chat', { messages: null, userId, receiverId: null, success: successMessage, receiverName: null, isAgent: null, chatList: processedChatList });
      }
    );
  }
});

newapp2.get('/customer-chat', (req, res) => {
    if (!req.user || req.user.role !== 'user') return res.redirect('/login');
    const clientId = req.session.userId || req.user.id;  // Use session or req.user
    connection.query('SELECT id FROM chats WHERE client_id = ? LIMIT 1', [clientId], (err, result) => {
        if (err) {
            console.error('Error checking chat:', err);
            return res.status(500).send('Server error');
        }
        let chatId = result[0]?.id;
        if (!chatId) {
            // Create chat with first available agent
            connection.query('SELECT id FROM signin WHERE role = "agent" LIMIT 1', (err, agents) => {
                if (err) {
                    console.error('Error finding agent:', err);
                    return res.status(500).send('No agents available');
                }
                if (agents.length === 0) return res.send('No agents available.');
                const agentId = agents[0].id;
                connection.query('INSERT INTO chats (agent_id, client_id) VALUES (?, ?)', [agentId, clientId], (err, insertResult) => {
                    if (err) {
                        console.error('Error creating chat:', err);
                        return res.status(500).send('Server error');
                    }
                    chatId = insertResult.insertId;
                    res.render('customer-chat', { chatId, clientId });
                });
            });
        } else {
            res.render('customer-chat', { chatId, clientId });
        }
    });
});

newapp2.get('/api/staff-list', ensureAuthenticated, (req, res) => {
  connection.query(
    "SELECT id, firstName, lastName, role FROM signin WHERE role IN ('admin', 'agent')",
    (err, results) => {
      if (err) return res.status(500).json([]);
      res.json(results);
    }
  );
});



newapp2.get('/inquiries', (req, res) => {
    if (!req.session || req.session.role !== 'agent') return res.redirect('/login');  // Restrict to agents/admins
    connection.query('SELECT * FROM enquiries ORDER BY timestamp DESC', (err, enquiries) => {
        if (err) {
            console.error('Error fetching enquiries:', err);
            return res.status(500).send('Server error');
        }
        res.render('enquiry', { enquiries });
    });
});


newapp2.get('/property-valuation',ensureAuthenticated, (req, res) => {
    res.render('property-valuation');
});


// Endpoint for property valuation

const groq = new Groq({ apiKey: "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" });
newapp2.post('/valuate', async (req, res) => {
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
  } catch (error) {
    console.error('Groq error:', error.message);
    res.status(500).json({ error: 'Valuation failed: ' + error.message });
  }
});



newapp2.post('/chat/send', ensureAuthenticated, (req, res) => {
  const { senderId, receiverId, message } = req.body;
  
  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const query = 'INSERT INTO chat_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())';
  connection.query(query, [senderId, receiverId, message], (err, result) => {
    if (err) {
      console.error('Error saving message:', err);
      return res.status(500).json({ error: 'Error saving message' });
    }
    console.log('Message saved to database:', { senderId, receiverId, message });
    res.json({ success: true, messageId: result.insertId });
  });
});



// Agent Chat Route
newapp2.get('/agent-chat', ensureAuthenticated, (req, res) => {
  const userId = req.user.id;
  const receiverId = req.query.receiverId;

  if (receiverId) {
    // Existing chat logic - show conversation with specific client
    connection.query("SELECT firstName, lastName, role FROM signin WHERE id = ?", [receiverId], (err, receiverResults) => {
      let receiverName = 'Unknown';
      let isClient = false;

      if (!err && receiverResults.length > 0) {
        const receiver = receiverResults[0];
        receiverName = `${receiver.firstName || ''} ${receiver.lastName || ''}`.trim();
        if (!receiverName) receiverName = 'Client';
        isClient = receiver.role === 'user';
      }

      connection.query(
        'SELECT * FROM chat_messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC',
        [userId, receiverId, receiverId, userId],
        (err, messages) => {
          if (err) return res.status(500).send('Error loading chat');
          res.render('agent-chat', { messages, userId, receiverId, receiverName, isClient, chatList: null });
        }
      );
    });
  } else {
    // Fetch chat list - all conversations where agent is the receiver
    connection.query(
      `SELECT DISTINCT 
         CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AS receiverId,
         s.firstName, s.lastName, s.role,
         (SELECT message FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessage,
         (SELECT timestamp FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessageTime
       FROM chat_messages cm
       JOIN signin s ON s.id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END
       WHERE cm.receiver_id = ?
       ORDER BY lastMessageTime DESC`,
      [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId],
      (err, chatList) => {
        if (err) {
          console.error('Chat list query error:', err);
          return res.status(500).send('Error loading chats');
        }
        const processedChatList = chatList.map(chat => ({
          receiverId: chat.receiverId,
          receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || 'Client',
          isClient: chat.role === 'user',
          lastMessage: chat.lastMessage,
          lastMessageTime: chat.lastMessageTime
        }));
        res.render('agent-chat', { messages: null, userId, receiverId: null, receiverName: null, isClient: null, chatList: processedChatList });
      }
    );
  }
});

// Agent send message route
newapp2.post('/agent-chat/send', ensureAuthenticated, (req, res) => {
  const { senderId, receiverId, message } = req.body;
  
  if (!senderId || !receiverId || !message) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const query = 'INSERT INTO chat_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, NOW())';
  connection.query(query, [senderId, receiverId, message], (err, result) => {
    if (err) {
      console.error('Error saving message:', err);
      return res.status(500).json({ error: 'Error saving message' });
    }
    console.log('Message saved to database:', { senderId, receiverId, message });
    res.json({ success: true, messageId: result.insertId });
  });
});




// Agent Chat Route
newapp2.get('/admin-chat', ensureAuthenticated, (req, res) => {
  const userId = req.user.id;
  const receiverId = req.query.receiverId;
  const userEmail = req.user.email; // Get the user email from the session

    if (!req.user) {
        return res.status(401).send('Unauthorized: Please log in first.');
    }
  if (receiverId) {
    // Existing chat logic - show conversation with specific client
    connection.query("SELECT firstName, lastName, role FROM signin WHERE id = ?", [receiverId], (err, receiverResults) => {
      let receiverName = 'Unknown';
      let isClient = false;

      if (!err && receiverResults.length > 0) {
        const receiver = receiverResults[0];
        receiverName = `${receiver.firstName || ''} ${receiver.lastName || ''}`.trim();
        if (!receiverName) receiverName = 'Client';
        isClient = receiver.role === 'user';
      }

      connection.query(
        'SELECT * FROM chat_messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC',
        [userId, receiverId, receiverId, userId],
        (err, messages) => {
          if (err) return res.status(500).send('Error loading chat');
          res.render('admin-chat', { messages, userId, receiverId, receiverName, isClient, chatList: null });
        }
      );
    });
 const isAdmin = userEmail === 'ibarealestate2023@gmail.com';
      connection.query("SELECT * FROM all_properties", (err, card) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Server error');
        } 

    });
  } else {
    // Fetch chat list - all conversations where agent is the receiver
    connection.query(
      `SELECT DISTINCT 
         CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AS receiverId,
         s.firstName, s.lastName, s.role,
         (SELECT message FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessage,
         (SELECT timestamp FROM chat_messages WHERE (sender_id = ? AND receiver_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END) OR (sender_id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END AND receiver_id = ?) ORDER BY timestamp DESC LIMIT 1) AS lastMessageTime
       FROM chat_messages cm
       JOIN signin s ON s.id = CASE WHEN cm.sender_id = ? THEN cm.receiver_id ELSE cm.sender_id END
       WHERE cm.receiver_id = ?
       ORDER BY lastMessageTime DESC`,
      [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId],
      (err, chatList) => {
        if (err) {
          console.error('Chat list query error:', err);
          return res.status(500).send('Error loading chats');
        }
        const processedChatList = chatList.map(chat => ({
          receiverId: chat.receiverId,
          receiverName: `${chat.firstName || ''} ${chat.lastName || ''}`.trim() || 'Client',
          isClient: chat.role === 'user',
          lastMessage: chat.lastMessage,
          lastMessageTime: chat.lastMessageTime
        }));
        res.render('admin-chat', { messages: null, userId, receiverId: null, receiverName: null, isClient: null, chatList: processedChatList });
      }
    );
  }
});



//gallery route 
newapp2.get('/gallery', (req, res) => {
    connection.query("SELECT * FROM all_properties ORDER BY id DESC", (err, card) => {
        if (err) return res.status(500).send('Server error');
        res.render('gallery', { card });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;

newapp2.listen(PORT, () => {
    newapp2.timeout = 0;
    console.log(`IBA Real Estate Server is running at port ${PORT}`);
});

//NOTES
// CREATE SEARCH BUTTON
//NAVIGATION FROM ONE TWO
//





