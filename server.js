require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const http = require('http');
const socketIo = require('socket.io');
const { Client, GatewayIntentBits, ChannelType } = require('discord.js');

const { User, Order, Staff, Thread, Blacklist } = require('./schemas');

// ==================================================================
// 1. INTERNAL DISCORD CLIENT (Runs inside Panel)
// ==================================================================
const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.DirectMessages, GatewayIntentBits.MessageContent]
});

// SETUP APP
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// DATABASE
mongoose.connect(process.env.MONGO_URI).then(() => console.log("✅ DB Connected"));

// OWNER INIT -> RENAMED TO JOSEPH
async function initOwner() {
    if (process.env.OWNER_ID && !(await Staff.findOne({ discordId: process.env.OWNER_ID }))) {
        await Staff.create({ username: 'Joseph', discordId: process.env.OWNER_ID, role: 'Owner' });
        console.log("👑 Owner Account 'Joseph' Created");
    }
}
initOwner();

// MIDDLEWARE
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({ secret: 'sugar_panel_secure', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// --- [FIX START] GLOBAL USER MIDDLEWARE ---
// This injects the logged-in user into EVERY view (sidebar, admin, etc.)
app.use((req, res, next) => {
    res.locals.user = req.user || null;
    next();
});
// --- [FIX END] ----------------------------

// ==================================================================
// 2. HYBRID AUTHENTICATION
// ==================================================================
passport.use(new LocalStrategy({ usernameField: 'username' }, 
    async (username, password, done) => {
        const user = await Staff.findOne({ username: username });
        if (!user || !user.password) return done(null, false, { message: 'Use Discord Login.' });
        if (!await user.validPassword(password)) return done(null, false, { message: 'Invalid Password.' });
        return done(null, user);
    }
));

passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    scope: ['identify'],
    passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
    try {
        // CASE A: Link Account
        if (req.user) {
            const existing = await Staff.findOne({ discordId: profile.id });
            if (existing && existing._id.toString() !== req.user._id.toString()) return done(null, false, { message: "ID Taken" });
            req.user.discordId = profile.id;
            req.user.avatar = profile.avatar;
            await req.user.save();
            return done(null, req.user);
        }
        // CASE B: Login
        const staff = await Staff.findOne({ discordId: profile.id });
        if (staff) {
            staff.username = profile.username;
            staff.avatar = profile.avatar;
            await staff.save();
            return done(null, staff);
        }
        return done(null, false, { message: "Access Denied." });
    } catch (err) { return done(err); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => done(null, await Staff.findById(id)));

const check = (roles) => (req, res, next) => {
    if (req.isAuthenticated()) {
        if (roles.includes('All') || roles.includes(req.user.role) || req.user.role === 'Admin') return next();
    }
    res.redirect('/');
};

// ==================================================================
// 3. ROUTES
// ==================================================================

app.get('/', (req, res) => {
    if(req.isAuthenticated()) return res.redirect('/dashboard');
    res.render('login', { msg: req.flash('error') });
});
app.post('/auth/login', passport.authenticate('local', { successRedirect: '/dashboard', failureRedirect: '/', failureFlash: true }));
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { successRedirect: '/dashboard', failureRedirect: '/', failureFlash: true }));
app.get('/logout', (req, res) => req.logout(() => res.redirect('/')));

app.get('/dashboard', check(['All']), async (req, res) => {
    if(req.user.firstLogin) return res.render('setup_password', { user: req.user });
    let stats = req.user.discordId ? await User.findOne({ user_id: req.user.discordId }) : null;
    res.render('dashboard', { user: req.user, stats });
});

app.post('/set-password', check(['All']), async (req, res) => {
    req.user.password = await bcrypt.hash(req.body.password, 10);
    req.user.firstLogin = false;
    await req.user.save();
    res.redirect('/dashboard');
});

// MANAGEMENT
app.get('/management', check(['Management', 'Senior', 'Owner']), async (req, res) => {
    const activeOrders = await Order.find({ status: { $ne: 'completed' } }).sort({ created_at: -1 });
    const warnedUsers = await User.find({ warnings: { $gt: 0 } });
    res.render('management', { activeOrders, warnedUsers });
});
app.post('/remove-warning', check(['Management', 'Senior', 'Owner']), async (req, res) => {
    await User.updateOne({ user_id: req.body.target_id }, { $inc: { warnings: -1 } });
    res.redirect('/management');
});

// SUPPORT (Uses Internal Client)
app.get('/support', check(['Management', 'Senior', 'Owner']), async (req, res) => {
    const threads = await Thread.find({ isOpen: true }).sort({ updatedAt: -1 });
    const blockedUsers = await User.find({ is_support_blocked: true }).distinct('user_id');
    res.render('support', { threads, blockedUsers });
});

app.post('/support/reply', check(['Management', 'Senior', 'Owner']), async (req, res) => {
    try {
        const thread = await Thread.findById(req.body.thread_id);
        thread.messages.push({ author: 'Staff', authorName: req.user.username, content: req.body.message, timestamp: new Date() });
        thread.updatedAt = new Date();
        await thread.save();

        const user = await client.users.fetch(thread.userId);
        await user.send(`**Support (${req.user.username}):** ${req.body.message}`);
        res.redirect('/support');
    } catch(e) { res.send("Error: Could not DM user."); }
});

app.post('/support/block', check(['Management', 'Senior', 'Owner']), async (req, res) => {
    await User.updateOne({ user_id: req.body.user_id }, { is_support_blocked: true });
    await Thread.updateMany({ userId: req.body.user_id }, { isOpen: false });
    res.redirect('/support');
});

// SERVERS & BLACKLIST
app.get('/servers', check(['Management', 'Senior', 'Owner']), (req, res) => res.render('servers'));

app.post('/blacklist', check(['Senior', 'Owner']), async (req, res) => {
    // Only saves to DB. DOES NOT LEAVE SERVER.
    await Blacklist.create({ guild_id: req.body.guild_id, reason: req.body.reason, authorized_by: req.user.username });
    res.redirect('/servers');
});

app.post('/generate-invite', check(['Management', 'Senior', 'Owner']), async (req, res) => {
    try {
        const guild = client.guilds.cache.get(req.body.guild_id);
        if(!guild) return res.send("Bot not in server");
        const channel = guild.channels.cache.find(c => c.type === ChannelType.GuildText && c.permissionsFor(guild.members.me).has('CreateInstantInvite'));
        if(channel) {
            const invite = await channel.createInvite({ maxAge: 3600, maxUses: 1 });
            io.emit('ui_invite', { code: invite.url });
            res.redirect('/servers');
        } else { res.send("No invite permission."); }
    } catch(e) { res.send("Error"); }
});

// ADMIN
app.get('/admin', check(['Admin', 'Owner']), async (req, res) => {
    const staff = await Staff.find({});
    res.render('admin', { staff });
});
app.post('/admin/create-local', check(['Admin', 'Owner']), async (req, res) => {
    const hash = await bcrypt.hash(req.body.password, 10);
    try { await Staff.create({ username: req.body.username, password: hash, role: req.body.role, firstLogin: true }); res.redirect('/admin'); } 
    catch(e) { res.send("Username taken"); }
});
app.post('/admin/create-discord', check(['Admin', 'Owner']), async (req, res) => {
    try { await Staff.create({ username: `Discord_${req.body.discord_id.substr(-4)}`, discordId: req.body.discord_id, role: req.body.role }); res.redirect('/admin'); } 
    catch(e) { res.send("ID taken"); }
});
app.post('/add-vip', check(['Owner']), async (req, res) => {
    const date = new Date(); date.setDate(date.getDate() + 30);
    await User.updateOne({ user_id: req.body.target_id }, { vip_until: date });
    res.redirect('/management');
});

// ==================================================================
// 4. REAL-TIME LOGIC
// ==================================================================
client.on('messageCreate', async (msg) => {
    if(msg.guild || msg.author.bot) return;

    const user = await User.findOne({ user_id: msg.author.id });
    if(user && user.is_support_blocked) return;

    let thread = await Thread.findOne({ userId: msg.author.id, isOpen: true });
    if(!thread) thread = await Thread.create({ userId: msg.author.id, username: msg.author.username, messages: [] });
    
    thread.messages.push({ author: 'User', authorName: msg.author.username, content: msg.content, timestamp: new Date() });
    thread.updatedAt = new Date();
    await thread.save();

    io.emit('ui_support_update', thread);
});

io.on('connection', (socket) => {
    const list = client.guilds.cache.map(g => ({ id: g.id, name: g.name, count: g.memberCount }));
    socket.emit('ui_server_list', list);
});

server.listen(3000, () => {
    console.log('🚀 Panel on Port 3000');
    client.login(process.env.DISCORD_TOKEN).then(() => console.log("🤖 Panel Client Logged In"));
});
