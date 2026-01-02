const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// 1. USER STATS (Shared with Main Bot)
const UserSchema = new mongoose.Schema({
    user_id: { type: String, required: true, unique: true },
    balance: { type: Number, default: 0 },
    warnings: { type: Number, default: 0 },
    cook_count_total: { type: Number, default: 0 },
    deliver_count_total: { type: Number, default: 0 },
    vip_until: { type: Date, default: new Date(0) },
    is_support_blocked: { type: Boolean, default: false }
});

// 2. ORDERS (Shared with Main Bot)
const OrderSchema = new mongoose.Schema({
    order_id: String,
    user_id: String,
    status: { type: String, default: 'pending' }, 
    item: String,
    is_vip: { type: Boolean, default: false },
    created_at: { type: Date, default: Date.now },
    chef_name: String,
    chef_id: String,
    rating: { type: Number, default: 0 }
});

// 3. STAFF ACCOUNTS (Hybrid Auth)
const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String }, // Optional
    discordId: { type: String, unique: true, sparse: true }, // Optional
    avatar: String,
    role: { 
        type: String, 
        default: 'Staff', 
        enum: ['Staff', 'Management', 'Senior', 'Owner', 'Admin'] 
    },
    firstLogin: { type: Boolean, default: false }
});

StaffSchema.methods.validPassword = async function(password) {
    if(!this.password) return false;
    return await bcrypt.compare(password, this.password);
};

// 4. SUPPORT THREADS
const ThreadSchema = new mongoose.Schema({
    userId: String,
    username: String,
    isOpen: { type: Boolean, default: true },
    updatedAt: { type: Date, default: Date.now },
    messages: [{
        author: String, // 'Staff' or 'User'
        authorName: String,
        content: String,
        timestamp: { type: Date, default: Date.now }
    }]
});

// 5. BLACKLIST
const BlacklistSchema = new mongoose.Schema({ 
    guild_id: String, 
    reason: String, 
    authorized_by: String 
});

module.exports = {
    User: mongoose.model('User', UserSchema),
    Order: mongoose.model('Order', OrderSchema),
    Staff: mongoose.model('Staff', StaffSchema),
    Thread: mongoose.model('Thread', ThreadSchema),
    Blacklist: mongoose.model('Blacklist', BlacklistSchema)
};
