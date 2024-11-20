const crypto = require('crypto');
const customerModel = require('../../models/customerModel');
const { responseReturn } = require('../../utiles/response');
const { createToken } = require('../../utiles/tokenCreate');
const sellerCustomerModel = require('../../models/chat/sellerCustomerModel');

class customerAuthController {
    /**
     * Hashes a password using crypto module.
     * @param {string} password - The plain text password.
     * @returns {string} - The hashed password.
     */
    hashPassword(password) {
        return crypto.createHmac('sha256', process.env.PASSWORD_SECRET).update(password).digest('hex');
    }

    /**
     * Compares a plain text password with a hashed password.
     * @param {string} plainPassword - The plain text password.
     * @param {string} hashedPassword - The hashed password.
     * @returns {boolean} - Whether the passwords match.
     */
    comparePassword(plainPassword, hashedPassword) {
        const hashed = this.hashPassword(plainPassword);
        return hashed === hashedPassword;
    }

    /**
     * Registers a new customer.
     */
    customer_register = async (req, res) => {
        const { name, email, password } = req.body;

        try {
            const customer = await customerModel.findOne({ email: email.trim() });
            if (customer) {
                return responseReturn(res, 400, { error: 'Email already exists' });
            }

            const hashedPassword = this.hashPassword(password);
            const createCustomer = await customerModel.create({
                name: name.trim(),
                email: email.trim(),
                password: hashedPassword,
                method: 'manual',
            });

            await sellerCustomerModel.create({ myId: createCustomer.id });

            const token = await createToken({
                id: createCustomer.id,
                name: createCustomer.name,
                email: createCustomer.email,
                method: createCustomer.method,
            });

            res.cookie('customerToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            });

            return responseReturn(res, 201, { message: 'Register success', token });
        } catch (error) {
            console.error(error.message);
            return responseReturn(res, 500, { error: 'Internal server error' });
        }
    };

    /**
     * Logs in an existing customer.
     */
    customer_login = async (req, res) => {
        const { email, password } = req.body;

        try {
            const customer = await customerModel.findOne({ email: email.trim() }).select('+password');
            if (!customer) {
                return responseReturn(res, 404, { error: 'Email not found' });
            }

            const isMatch = this.comparePassword(password, customer.password);
            if (!isMatch) {
                return responseReturn(res, 401, { error: 'Password is incorrect' });
            }

            const token = await createToken({
                id: customer.id,
                name: customer.name,
                email: customer.email,
                method: customer.method,
            });

            res.cookie('customerToken', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            });

            return responseReturn(res, 200, { message: 'Login success', token });
        } catch (error) {
            console.error(error.message);
            return responseReturn(res, 500, { error: 'Internal server error' });
        }
    };

    /**
     * Logs out a customer.
     */
    customer_logout = async (req, res) => {
        try {
            res.cookie('customerToken', '', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                expires: new Date(0),
            });

            return responseReturn(res, 200, { message: 'Logout success' });
        } catch (error) {
            console.error(error.message);
            return responseReturn(res, 500, { error: 'Internal server error' });
        }
    };
}

module.exports = new customerAuthController();
