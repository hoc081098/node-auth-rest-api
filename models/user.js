const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const config = require('../config/config.json');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    maxlength: 50
  },
  email: {
    unique: true,
    index: true,
    type: String,
    required: true,
    validate: {
      validator: (v) =>
        /^[a-zA-Z0-9\+\.\_\%\-\+]{1,256}\@[a-zA-Z0-9][a-zA-Z0-9\-]{0,64}(\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,25})+$/gi.test(v),
      message: '{VALUE} is not a valid email address!'
    },
  },
  hashed_password: {
    type: String,
    required: true
  },
  created_at: {
    type: Date,
    default: Date.now,
    required: true,
  },
  temp_hashed_password: String,
  temp_hashed_password_time: Date,
  image_url: {
    type: String,
    default: undefined,
  }
});

const User = module.exports = mongoose.model('users', userSchema);

module.exports.findUserByEmail = async (email, projection) => {
  const docs = await User.find({
    email: email
  }, projection).limit(1).exec();
  if (docs.length === 0) {
    throw {
      status: 404,
      message: 'User not found!'
    };
  }
  return docs[0];
}

async function hash(s) {
  const salt = await bcryptjs.genSalt(10);
  const hashed = await bcryptjs.hash(s, salt);
  return hashed;
}

module.exports.registerUser = async (name, email, password) => {
  try {
    const hashedPassword = await hash(password);

    const user = new User({
      name: name,
      email: email,
      hashed_password: hashedPassword,
      created_at: new Date()
    });

    await user.save();
    return {
      status: 201,
      message: 'User registered successfully'
    };
  } catch (e) {
    console.log(e);
    if (e.code === 11000) throw {
      status: 409,
      message: 'User already registered!'
    };
    throw e;
  }
};

module.exports.loginUser = async (email, password) => {
  const user = await User.findUserByEmail(email);
  const hashedPassword = user.hashed_password;
  const success = await bcryptjs.compare(password, hashedPassword);
  if (success) {
    return {
      status: 200,
      message: email
    };
  } else {
    throw {
      status: 401,
      message: 'Invalid credential!'
    };
  }
};

module.exports.getProfile = (email) => User.findUserByEmail(email, {
  name: 1,
  email: 1,
  created_at: 1,
  image_url: 1,
  _id: 0
});

module.exports.changePassword = async (email, password, newPassword) => {
  const user = await User.findUserByEmail(email);
  const success = await bcryptjs.compare(password, user.hashed_password);
  if (!success) {
    throw {
      status: 401,
      message: 'Invalid old password'
    };
  }
  user.hashed_password = await hash(newPassword);
  await user.save();
  return {
    status: 200,
    message: 'Update password successfully!'
  };
};

function randomString(length) {
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from(Array(length), (index) => {
    const i = Math.floor(Math.random() * possible.length);
    return possible.charAt(i);
  }).join('');
}

module.exports.resetPasswordInit = async (email) => {
  const user = await User.findUserByEmail(email);
  const random = randomString(8);
  const hashed = await hash(random);

  user.temp_hashed_password = hashed;
  user.temp_hashed_password_time = new Date();

  const user1 = await user.save();

  console.log("send email");

  const transpoter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: config.email, // generated ethereal user
      pass: config.email_password // generated ethereal password
    },

  });
  console.log(transpoter);
  // const transpoter = nodemailer.createTransport(`smtps://${config.email}:${config.email_password}@smtp.gmail.com`);
  const mailOptions = {
    from: `${config.name} ✔ <${config.email}>`,
    to: email,
    subject: 'Reset password request',
    html: `Hello ${user1.name}, your reset password token is <strong>${random}</strong>. This token is valid for only 2 minutes.<br/>Thank you, ${config.name}`
  };
  console.log('before send');
  const info = await transpoter.sendMail(mailOptions);
  console.log("Done");
  return {
    status: 200,
    message: 'Check mail for instruction'
  };
};

module.exports.updateImageUrl = async (email, imageUrl) => {
  const user = await User.findUserByEmail(email);
  user.image_url = imageUrl;
  return await user.save();
};

module.exports.resetPasswordFinish = async (email, token, password) => {
  console.log("Reset password ", email, token, password);
  const user = await User.findUserByEmail(email);
  const diff = new Date().getTime() - new Date(user.temp_hashed_password_time).getTime();
  if (diff >= 2 * 60 * 1000) {
    throw {
      status: 401,
      message: 'Time out! Try again'
    };
  }
  const success = await bcryptjs.compare(token, user.temp_hashed_password);
  if (!success) {
    throw {
      status: 401,
      message: 'Invalid token!'
    };
  }

  user.hashed_password = await hash(password);
  user.temp_hashed_password = undefined;
  user.temp_hashed_password_time = undefined;
  await user.save();

  return {
    status: 200,
    message: 'Password changed sucessfully'
  };
};