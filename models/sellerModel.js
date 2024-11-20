const { Schema, model } = require('mongoose');

const sellerSchema = new Schema(
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
            select: false, // Exclude from queries by default
        },
        salt: {
            type: String,
            select: false, // For password salting, excluded from queries
        },
        role: {
            type: String,
            enum: ['seller', 'admin'], // Valid roles for sellers
            default: 'seller',
        },
        status: {
            type: String,
            enum: ['pending', 'active', 'suspended'], // Controlled values
            default: 'pending',
        },
        payment: {
            type: String,
            enum: ['inactive', 'active', 'delinquent'], // Payment states
            default: 'inactive',
        },
        method: {
            type: String,
            enum: ['manual', 'oauth'], // Login/registration method
            required: true,
        },
        image: {
            type: String,
            default: '', // Default if no image is uploaded
        },
        shopInfo: {
            type: Map, // Allows structured key-value storage
            of: String, // Each value in `shopInfo` is a string
            default: {}, // Default to an empty object
        },
    },
    {
        timestamps: true, // Adds createdAt and updatedAt fields
    }
);

// Text indexing for optimized search functionality
sellerSchema.index(
    { name: 'text', email: 'text' },
    {
        weights: {
            name: 5, // Higher weight to prioritize name in search
            email: 4,
        },
    }
);

module.exports = model('Seller', sellerSchema);
