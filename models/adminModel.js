const { Schema, model } = require('mongoose');

const adminSchema = new Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
        },
        password: {
            type: String,
            required: true,
            select: false, // Exclude by default when querying
        },
        salt: {
            type: String,
            required: true,
            select: false, // Exclude by default when querying
        },
        image: {
            type: String,
            default: '', // Default value if image is not provided
        },
        role: {
            type: String,
            enum: ['admin', 'superadmin'], // Ensures valid roles
            default: 'admin',
        },
    },
    {
        timestamps: true, // Automatically adds createdAt and updatedAt fields
    }
);

module.exports = model('Admin', adminSchema);
