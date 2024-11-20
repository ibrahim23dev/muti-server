const crypto = require('crypto');
const formidable = require('formidable');
const cloudinary = require('cloudinary').v2;
const adminModel = require('../models/adminModel');
const sellerModel = require('../models/sellerModel');
const sellerCustomerModel = require('../models/chat/sellerCustomerModel');
const { responseReturn } = require('../utiles/response');
const { createToken } = require('../utiles/tokenCreate');

// Helper function to hash passwords using crypto with salt
const hashPassword = (password, salt = crypto.randomBytes(16).toString('hex')) => {
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return { salt, hash };
};

// Helper function to verify hashed passwords
const comparePassword = (inputPassword, storedHash, storedSalt) => {
    const { hash } = hashPassword(inputPassword, storedSalt);
    return hash === storedHash;
};

class AuthControllers {
    admin_login = async (req, res) => {
        const { email, password } = req.body;
        try {
            const admin = await adminModel.findOne({ email }).select('+password +salt');
            if (admin) {
                const match = comparePassword(password, admin.password, admin.salt);
                if (match) {
                    const token = await createToken({ id: admin.id, role: admin.role });
                    res.cookie('accessToken', token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                    });
                    responseReturn(res, 200, { token, message: 'Login success' });
                } else {
                    responseReturn(res, 400, { error: 'Password incorrect' });
                }
            } else {
                responseReturn(res, 404, { error: 'Email not found' });
            }
        } catch (error) {
            responseReturn(res, 500, { error: error.message });
        }
    };

    seller_login = async (req, res) => {
        const { email, password } = req.body;
        try {
            const seller = await sellerModel.findOne({ email }).select('+password +salt');
            if (seller) {
                const match = comparePassword(password, seller.password, seller.salt);
                if (match) {
                    const token = await createToken({ id: seller.id, role: seller.role });
                    res.cookie('accessToken', token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                    });
                    responseReturn(res, 200, { token, message: 'Login success' });
                } else {
                    responseReturn(res, 400, { error: 'Password incorrect' });
                }
            } else {
                responseReturn(res, 404, { error: 'Email not found' });
            }
        } catch (error) {
            responseReturn(res, 500, { error: error.message });
        }
    };

    seller_register = async (req, res) => {
        const { email, name, password } = req.body;
        try {
            const existingUser = await sellerModel.findOne({ email });
            if (existingUser) {
                responseReturn(res, 404, { error: 'Email already exists' });
            } else {
                const { hash, salt } = hashPassword(password);
                const seller = await sellerModel.create({
                    name,
                    email,
                    password: hash,
                    salt,
                    method: 'manual',
                    shopInfo: {},
                });
                await sellerCustomerModel.create({ myId: seller.id });
                const token = await createToken({ id: seller.id, role: seller.role });
                res.cookie('accessToken', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                });
                responseReturn(res, 201, { token, message: 'Registration success' });
            }
        } catch (error) {
            responseReturn(res, 500, { error: 'Internal server error' });
        }
    };

     getUser = async (req, res) => {
        const { id, role } = req;
        try {
            const user = role === 'admin' 
                ? await adminModel.findById(id) 
                : await sellerModel.findById(id);
            responseReturn(res, 200, { userInfo: user });
        } catch (error) {
            responseReturn(res, 500, { error: 'Internal server error' });
        }
    };

    profile_image_upload = async (req, res) => {
        const { id } = req;
        const form = formidable({ multiples: true });
        form.parse(req, async (err, _, files) => {
            if (err) {
                return responseReturn(res, 400, { error: 'Form parsing failed' });
            }
            cloudinary.config({
                cloud_name: process.env.CLOUD_NAME,
                api_key: process.env.API_KEY,
                api_secret: process.env.API_SECRET,
                secure: true,
            });
            const { image } = files;
            try {
                const result = await cloudinary.uploader.upload(image.filepath, { folder: 'profile' });
                if (result) {
                    await sellerModel.findByIdAndUpdate(id, { image: result.url });
                    const userInfo = await sellerModel.findById(id);
                    responseReturn(res, 201, { message: 'Image upload success', userInfo });
                } else {
                    responseReturn(res, 404, { error: 'Image upload failed' });
                }
            } catch (error) {
                responseReturn(res, 500, { error: error.message });
            }
        });
    };

    profile_info_add = async (req, res) => {
        const { division, district, shopName, sub_district } = req.body;
        const { id } = req;
        try {
            await sellerModel.findByIdAndUpdate(id, {
                shopInfo: { shopName, division, district, sub_district },
            });
            const userInfo = await sellerModel.findById(id);
            responseReturn(res, 201, { message: 'Profile info added successfully', userInfo });
        } catch (error) {
            responseReturn(res, 500, { error: error.message });
        }
    };

    logout = async (req, res) => {
        try {
            res.cookie('accessToken', null, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                expires: new Date(Date.now()),
            });
            responseReturn(res, 200, { message: 'Logout success' });
        } catch (error) {
            responseReturn(res, 500, { error: error.message });
        }
    };
}

module.exports = new AuthControllers();
