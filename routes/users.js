var express = require('express');
var router = express.Router();
const auth = require('basic-auth');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const config = require('../config/config.json');
const multer = require('multer');
const path = require('path');

/* Login */
router.post('/authenticate', (req, res) => {
  const credentials = auth(req);
  if (!credentials) {
    return res.status(400).json({
      message: 'Invalid request!'
    });
  }
  console.log(credentials);
  User.loginUser(credentials.name, credentials.pass)
    .then(result => {
      const token = jwt.sign(result, config.secret_key, {
        expiresIn: 604800
      });
      res.status(result.status).json({
        message: result.message,
        token: token
      });
    })
    .catch(e => {
      if (e.status) {
        res.status(e.status).json({
          message: e.message
        });
      } else {
        res.status(500).json({
          message: 'Internal server error!'
        });
      }
    });
});

/* Register */
router.post('/', (req, res) => {
  console.log("Register body: ", req.body);
  const {
    name,
    email,
    password
  } = req.body;
  if (!name || !email || !password || !name.trim() || !email.trim() || !password.trim()) {
    return res.status(400).json({
      message: 'Invalid request!'
    });
  }

  User.registerUser(name, email, password)
    .then(result => {
      res.setHeader('Location', `/users/${email}`);
      res.status(result.status).json({
        message: result.message
      });
    })
    .catch(e => {
      if (e.status) {
        res.status(e.status).json({
          message: e.message
        });
      } else {
        res.status(500).json({
          message: 'Internal server error!'
        });
      }
    });
});

/* Get user profile */
router.get('/:email', (req, res) => {
  if (!checkToken(req)) {
    return res.status(401).json({
      message: 'Invalid token!'
    });
  }
  User.getProfile(req.params.email)
    .then(result => {
      res.status(200).json(result);
    })
    .catch(e => {
      if (e.status) {
        res.status(e.status).json({
          message: e.message
        });
      } else {
        res.status(500).json({
          message: 'Internal server error!'
        });
      }
    });
});

/* Change password */
router.put('/:email/password', (req, res) => {
  if (!checkToken(req)) {
    return res.status(401).json({
      message: 'Invalid token!'
    });
  }
  const {
    password,
    new_password
  } = req.body;
  const email = req.params.email;
  console.log("PUT /:email/password: ", req.body, ", ", email);

  if (!password || !new_password || !password.trim() || !new_password.trim()) {
    return res.status(400).json({
      message: 'Invalid request!'
    });
  }

  User.changePassword(email, password, new_password)
    .then(result => {
      res.status(result.status).json({
        message: result.message
      });
    })
    .catch(e => {
      if (e.status) {
        res.status(e.status).json({
          message: e.message
        });
      } else {
        res.status(500).json({
          message: 'Internal server error!'
        });
      }
    });
});

/* Reset password, if body is empty, send a token to :email.
 * Sending body with token and new password to reset the password
 */
router.post('/:email/password', (req, res) => {
  const email = req.params.email;
  const {
    token,
    new_password
  } = req.body;

  console.log(email, ">>", token, ">>", new_password);

  const task = !token || !new_password || !token.trim() || !new_password.trim() ?
    User.resetPasswordInit(email) :
    User.resetPasswordFinish(email, token, new_password);
  console.log(task);
  task
    .then(result => {
      res.status(result.status).json({
        message: result.message
      });
    })
    .catch(e => {
      console.error(e);

      if (e.status) {
        res.status(e.status).json({
          message: e.message
        });
      } else {
        res.status(500).json({
          message: 'Internal server error!'
        });
      }
    });
});

/* Upload image */

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, './public/images');
  },
  filename: function(req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const extensions = /\.(jpg|png)/gi;
    const ext = path.extname(file.originalname);
    if (ext && extensions.test(ext)) {
      return cb(null, true);
    }
    return cb(Error('Only accept .jpg, .png!'), false);
  }
}).single('my_image');

router.post('/upload', (req, res) => {
  upload(req, res, err => {
    if (err) {
      return res.status(500).json({
        message: err.message
      });
    }
    const path = req.file.path;
    User.updateImageUrl(req.body.user, path.substring(path.indexOf('/')))
      .then(user => {
        res.status(200).json(user);
      })
      .catch(err => {
        res.status(500).json({
          message: err.message || 'Internal server error!'
        });
      });
  });
});

function checkToken(req) {
  const token = req.get('x-access-token');
  if (!token) return false;
  try {
    const decoded = jwt.verify(token, config.secret_key);
    return decoded.message === req.params.email;
  } catch (e) {
    return false;
  }
}

module.exports = router;