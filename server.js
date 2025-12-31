require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo'); 
const passport = require('passport');
const { Strategy: DiscordStrategy } = require('passport-discord');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const flash = require('connect-flash');
const multer = require('multer');
const { Client, GatewayIntentBits, AttachmentBuilder, Partials, ChannelType, PermissionsBitField } = require('discord.js');

// --- CONFIGURATION ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const upload = multer({ storage: multer.memoryStorage() });

const PORT = process.env.PORT || 3000; 
const MONGO_URI = process.env.MONGO_URI;
const TOKEN = process.env.DISCORD_TOKEN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CALLBACK_URL = process.env.CALLBACK_URL || "http://localhost:3000/auth/discord/callback";
const TRANSCRIPT_CHANNEL_ID = '1454888266451910901'; 
const MASTER_ID = '662655499811946536';

// --- INTERNAL BOT CLIENT ---
const bot = new Client({ 
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.DirectMessages, GatewayIntentBits.MessageContent],
    partials: [Partials.Channel, Partials.Message] 
});

bot.once('ready', () => {
    console.log(`🤖 Bot Logged in as ${bot.user.tag}`);
    console.log(`📊 Cached ${bot.guilds.cache.size} Servers`);
});
bot.login(TOKEN);

// --- DATABASE SCHEMAS ---
const UserSchema = new mongoose.Schema({
    user_id: { type: String, required: true, unique: true },
    balance: { type: Number, default: 0 },
    last_daily: { type: Date, default: new Date(0) },
    cook_count_week: { type: Number, default: 0 },
    cook_count_total: { type: Number, default: 0 },
    deliver_count_week: { type: Number, default: 0 },
    deliver_count_total: { type: Number, default: 0 },
    vip_until: { type: Date, default: new Date(0) },
    is_perm_banned: { type: Boolean, default: false },
    service_ban_until: { type: Date, default: null },
    double_stats_until: { type: Date, default: new Date(0) },
    warnings: { type: Number, default: 0 }
});

const OrderSchema = new mongoose.Schema({
    order_id: String,
    user_id: String,
    guild_id: String,
    channel_id: String,
    status: { type: String, default: 'pending' }, 
    item: String,
    is_vip: { type: Boolean, default: false },
    is_super: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
    chef_name: String,
    chef_id: String,
    deliverer_id: String,
    delivery_started_at: Date, 
    ready_at: Date,
    images: [String],
    kitchen_msg_id: String,
    rating: { type: Number, default: 0 },
    feedback: { type: String, default: "" },
    rated: { type: Boolean, default: false },
    backup_msg_id: String
});

const VIPCodeSchema = new mongoose.Schema({ code: { type: String, unique: true }, is_used: { type: Boolean, default: false } });
const ScriptSchema = new mongoose.Schema({ user_id: String, script: String });
const BlacklistSchema = new mongoose.Schema({ guild_id: String, reason: String, authorized_by: String });
const ConfigSchema = new mongoose.Schema({ id: { type: String, default: 'main' }, last_quota_run: { type: Date, default: new Date(0) } });

const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }, 
    role: { type: String, default: 'Staff', enum: ['Owner', 'Staff'] }, 
    discordId: { type: String, default: null } 
});

const ThreadSchema = new mongoose.Schema({
    userId: String,
    username: String,
    avatar: String,
    isOpen: { type: Boolean, default: true },
    updatedAt: { type: Date, default: Date.now },
    messages: [{
        author: String,
        authorName: String,
        avatar: String,
        content: String,
        attachment: String,
        timestamp: { type: Date, default: Date.now }
    }]
});

const User = mongoose.model('User', UserSchema);
const Order = mongoose.model('Order', OrderSchema);
const VIPCode = mongoose.model('VIPCode', VIPCodeSchema);
const Script = mongoose.model('Script', ScriptSchema);
const ServerBlacklist = mongoose.model('ServerBlacklist', BlacklistSchema);
const SystemConfig = mongoose.model('SystemConfig', ConfigSchema);
const WebStaff = mongoose.model('WebStaff', StaffSchema);
const Thread = mongoose.model('Thread', ThreadSchema);

mongoose.connect(MONGO_URI).then(async () => {
    console.log('✅ MongoDB Connected (Panel)');
    const ownerExists = await WebStaff.findOne({ role: 'Owner' });
    if (!ownerExists) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await new WebStaff({ username: 'admin', password: hashedPassword, role: 'Owner' }).save();
        console.log('👑 Default Owner Account Created: User: admin | Pass: admin123');
    }
});

// --- MIDDLEWARE ---
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(flash());

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || 'sugar_rush_secret_key_secure',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } 
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

const wrap = middleware => (socket, next) => middleware(socket.request, {}, next);
io.use(wrap(sessionMiddleware));
io.use(wrap(passport.initialize()));
io.use(wrap(passport.session()));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    const user = await WebStaff.findById(id);
    done(null, user);
});

passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await WebStaff.findOne({ username });
        if (!user) return done(null, false, { message: 'Bad credentials.' });
        const match = await bcrypt.compare(password, user.password);
        if (!match) return done(null, false, { message: 'Bad credentials.' });
        return done(null, user);
    } catch (e) { return done(e); }
}));

passport.use(new DiscordStrategy({
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackURL: CALLBACK_URL,
    scope: ['identify'],
    passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
    if (req.user) {
        req.user.discordId = profile.id;
        await req.user.save();
        return done(null, req.user);
    } else {
        const user = await WebStaff.findOne({ discordId: profile.id });
        if (!user) return done(null, false, { message: 'No linked staff account found.' });
        return done(null, user);
    }
}));

function isStaff(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/');
}

function isOwner(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'Owner') return next();
    req.flash('error', 'Owner access required.');
    res.redirect('/dashboard');
}

io.on('connection', (socket) => {
    socket.on('join_thread', (threadId) => socket.join(threadId));
});

// --- FIXED MESSAGE HANDLER ---
bot.on('messageCreate', async (message) => {
    if (message.author.bot || message.guild) return;

    try {
        console.log(`📨 DM Received from ${message.author.tag}`);
        let thread = await Thread.findOne({ userId: message.author.id, isOpen: true });
        
        if (!thread) {
            console.log("🆕 Creating new support thread...");
            thread = new Thread({
                userId: message.author.id,
                username: message.author.username,
                avatar: message.author.displayAvatarURL(),
                messages: []
            });
            await message.author.send("📩 **Support Ticket Created.** A staff member will be with you shortly.")
                .catch(e => console.error("⚠️ Could not send Auto-Reply:", e.message));
        }

        const newMessage = {
            author: 'User',
            authorName: message.author.username,
            avatar: message.author.displayAvatarURL(),
            content: message.content || '(Attachment)',
            attachment: message.attachments.first() ? message.attachments.first().url : null,
            timestamp: new Date()
        };

        thread.messages.push(newMessage);
        thread.updatedAt = new Date();
        await thread.save();

        io.to(thread._id.toString()).emit('new_message', newMessage);
        console.log("✅ DM Saved & Emitted");
    } catch (err) { console.error("🔥 ERROR in messageCreate:", err); }
});

// --- ROUTES ---
app.get('/', (req, res) => res.render('login', { message: req.flash('error') }));
app.post('/login', passport.authenticate('local', { successRedirect: '/dashboard', failureRedirect: '/', failureFlash: true }));
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', passport.authenticate('discord', { failureRedirect: '/', failureFlash: true }), (req, res) => res.redirect('/dashboard'));
app.get('/logout', (req, res) => { req.logout(() => res.redirect('/')); });

app.get('/dashboard', isStaff, async (req, res) => {
    const threads = await Thread.find({ isOpen: true }).sort({ updatedAt: -1 });
    const users = await User.find({ $or: [{ warnings: { $gt: 0 } }, { is_perm_banned: true }] }).sort({ warnings: -1 });
    res.render('dashboard', { user: req.user, threads, warnedUsers: users, success_msg: req.flash('success'), error_msg: req.flash('error') });
});

app.get('/profile', isStaff, (req, res) => res.render('profile', { user: req.user, success_msg: req.flash('success'), error_msg: req.flash('error') }));

app.post('/profile/password', isStaff, async (req, res) => {
    const { current_password, new_password } = req.body;
    const match = await bcrypt.compare(current_password, req.user.password);
    if (!match) { req.flash('error', 'Incorrect password.'); return res.redirect('/profile'); }
    req.user.password = await bcrypt.hash(new_password, 10);
    await req.user.save();
    req.flash('success', 'Password updated.');
    res.redirect('/profile');
});

app.get('/orders', isStaff, async (req, res) => {
    const orders = await Order.find().sort({ created_at: -1 });
    res.render('staff_orders', { user: req.user, orders, success_msg: req.flash('success'), error_msg: req.flash('error') });
});

app.get('/admin/staff', isOwner, async (req, res) => {
    const allStaff = await WebStaff.find({});
    res.render('admin_staff', { user: req.user, staffList: allStaff, success_msg: req.flash('success'), error_msg: req.flash('error') });
});

app.post('/admin/staff/create', isOwner, async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (await WebStaff.findOne({ username })) { req.flash('error', 'Username taken.'); return res.redirect('/admin/staff'); }
        await new WebStaff({ username, password: await bcrypt.hash(password, 10), role }).save();
        req.flash('success', `Created ${role}: ${username}`);
    } catch (e) { req.flash('error', 'Error creating staff.'); }
    res.redirect('/admin/staff');
});

app.post('/admin/staff/role', isOwner, async (req, res) => {
    const target = await WebStaff.findById(req.body.id);
    if (!target) return res.redirect('/admin/staff');
    if (target.discordId === MASTER_ID) { req.flash('error', '⛔ MASTER OVERRIDE: Cannot demote Owner.'); return res.redirect('/admin/staff'); }
    if (req.body.id == req.user._id && req.body.new_role === 'Staff') { req.flash('error', 'Cannot demote self.'); return res.redirect('/admin/staff'); }
    target.role = req.body.new_role;
    await target.save();
    req.flash('success', `Role updated to ${req.body.new_role}.`);
    res.redirect('/admin/staff');
});

app.post('/admin/staff/delete', isOwner, async (req, res) => {
    const target = await WebStaff.findById(req.body.id);
    if (!target) return res.redirect('/admin/staff');
    if (target.discordId === MASTER_ID) { req.flash('error', '⛔ MASTER OVERRIDE: Cannot delete Owner.'); return res.redirect('/admin/staff'); }
    if (req.body.id == req.user._id) { req.flash('error', 'Cannot delete self.'); return res.redirect('/admin/staff'); }
    await WebStaff.findByIdAndDelete(req.body.id);
    req.flash('success', 'Account deleted.');
    res.redirect('/admin/staff');
});

app.post('/admin/staff/reset', isOwner, async (req, res) => {
    await WebStaff.findByIdAndUpdate(req.body.id, { password: await bcrypt.hash(req.body.new_password, 10) });
    req.flash('success', 'Password reset.');
    res.redirect('/admin/staff');
});

app.get('/admin/servers', isOwner, async (req, res) => {
    const blacklisted = await ServerBlacklist.find({});
    const activeServers = bot.guilds.cache.map(g => ({ id: g.id, name: g.name, memberCount: g.memberCount, icon: g.iconURL() }));
    res.render('admin_servers', { user: req.user, activeServers, blacklisted, success_msg: req.flash('success'), error_msg: req.flash('error') });
});

app.post('/admin/blacklist/add', isOwner, async (req, res) => {
    await new ServerBlacklist({ guild_id: req.body.guild_id, reason: req.body.reason, authorized_by: req.user.username }).save();
    const guild = bot.guilds.cache.get(req.body.guild_id);
    if (guild) await guild.leave();
    req.flash('success', 'Server blacklisted.');
    res.redirect('/admin/servers');
});

app.post('/admin/blacklist/remove', isOwner, async (req, res) => {
    await ServerBlacklist.findByIdAndDelete(req.body.id);
    req.flash('success', 'Removed from blacklist.');
    res.redirect('/admin/servers');
});

// --- FIXED INVITE LOGIC ---
app.post('/admin/server/invite', isOwner, async (req, res) => {
    try {
        const guild = bot.guilds.cache.get(req.body.guild_id);
        if (!guild) throw new Error('Bot not in server.');
        const me = guild.members.me || await guild.members.fetchMe().catch(() => null);
        if (!me) throw new Error('Cannot fetch bot permissions.');

        let channel = guild.systemChannel;
        if (!channel || !channel.permissionsFor(me).has(PermissionsBitField.Flags.CreateInstantInvite)) {
            channel = guild.channels.cache.find(c => 
                (c.type === ChannelType.GuildText || c.type === ChannelType.GuildAnnouncement) && 
                c.permissionsFor(me).has(PermissionsBitField.Flags.CreateInstantInvite)
            );
        }

        if (!channel) throw new Error('No channel found with Invite permissions.');
        const invite = await channel.createInvite({ maxAge: 3600, maxUses: 1 });
        req.flash('success', `Invite: ${invite.url}`);
    } catch (e) { req.flash('error', `Error: ${e.message}`); }
    res.redirect('/admin/servers');
});

app.get('/mail/:threadId', isStaff, async (req, res) => {
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) return res.redirect('/dashboard');
    res.render('mail_thread', { user: req.user, thread });
});

app.post('/mail/:threadId/reply', isStaff, upload.single('image'), async (req, res) => {
    try {
        const thread = await Thread.findById(req.params.threadId);
        if (!thread || !thread.isOpen) return res.status(400).json({error: "Closed"});
        const discordUser = await bot.users.fetch(thread.userId);
        
        const content = req.body.content || '';
        if (!content && !req.file) throw new Error("Cannot send empty message.");

        const msgPayload = { content: `**👨‍🍳 ${req.user.username}:** ${content}` };
        if (req.file) { msgPayload.files = [new AttachmentBuilder(req.file.buffer, { name: req.file.originalname })]; }

        const sentMsg = await discordUser.send(msgPayload);
        const newMessage = { 
            author: 'Staff', authorName: req.user.username, avatar: 'https://cdn.discordapp.com/embed/avatars/0.png', 
            content: content || '(Image Sent)', attachment: sentMsg.attachments.first() ? sentMsg.attachments.first().url : null, timestamp: new Date() 
        };

        thread.messages.push(newMessage);
        thread.updatedAt = new Date();
        await thread.save();

        io.to(thread._id.toString()).emit('new_message', newMessage);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) return res.json({ success: true });
        res.redirect(`/mail/${thread._id}`);
    } catch (e) { 
        console.error("DM Error:", e);
        if (req.xhr) return res.status(500).json({ error: "Failed to send DM." }); 
        res.redirect('back'); 
    }
});

app.post('/mail/:threadId/archive', isStaff, async (req, res) => {
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) return res.redirect('/dashboard');
    const lines = thread.messages.map(m => `[${m.timestamp.toLocaleString()}] ${m.authorName}: ${m.content}`).join('\n');
    const attachment = new AttachmentBuilder(Buffer.from(lines), { name: `log-${thread.username}.txt` });
    const channel = bot.channels.cache.get(TRANSCRIPT_CHANNEL_ID);
    if (channel) await channel.send({ content: `🔒 **Archived:** ${thread.username} (<@${thread.userId}>) by ${req.user.username}`, files: [attachment] });
    await Thread.findByIdAndDelete(req.params.threadId);
    res.redirect('/dashboard');
});

app.post('/warn', isStaff, async (req, res) => {
    const { target_id, action } = req.body;
    const userData = await User.findOne({ user_id: target_id }) || new User({ user_id: target_id });
    if (action === 'add') { 
        userData.warnings += 1; 
        if (userData.warnings === 3) userData.service_ban_until = new Date(Date.now() + 7 * 86400000);
        else if (userData.warnings === 6) userData.service_ban_until = new Date(Date.now() + 30 * 86400000);
        else if (userData.warnings >= 9) userData.is_perm_banned = true; 
    }
    else if (action === 'clear') { userData.warnings = 0; userData.is_perm_banned = false; userData.service_ban_until = null; }
    await userData.save();
    res.redirect('/dashboard');
});

app.post('/vip', isStaff, async (req, res) => {
    const { target_id, days } = req.body;
    const userData = await User.findOne({ user_id: target_id }) || new User({ user_id: target_id });
    const addTime = parseInt(days) * 24 * 60 * 60 * 1000;
    const currentExpiry = userData.vip_until > new Date() ? userData.vip_until.getTime() : Date.now();
    userData.vip_until = new Date(currentExpiry + addTime);
    await userData.save();
    res.redirect('/dashboard');
});

server.listen(PORT, () => console.log(`💻 Panel + Socket.io running on Port ${PORT}`));
