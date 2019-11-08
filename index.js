var _ = require('lodash');
var moment = require('moment');
var uuid = require('uuid');
var bcrypt = require('bcryptjs');
var debug = require('debug')('gr8:security');
var verbose = require('debug')('gr8:security:verbose');


/**
  Authentication functions supported are:
  1. login - performs authentication
  2. generateResetPasswordToken - generates a token that can be used to obtain a new password
  3. resetPassword - saves a new password

  @param {object} daoFactory data access object factory (see ./db/database)
  @param {object} options object for controlling logins, encryption strength
  @example {
    max_bad_logins: 10,
    salt_rounds: 15,
    security_logger: <winston logger>
  }
  @module security
*/
class AuthService {
  constructor (daoFactory, opts) {
    this.userDao = daoFactory.User();
    this.userRoleDao = daoFactory.UserRole();
  }

  /**
   * Logs in a user and returns the user if successful.
   * The password is compared against the hash stored in the database. 
   * An error message is thrown carrying a message that is generally suitable for 
   * display to the end-user (does not divulge PII).
   * 
   * @param {string} username 
   * @param {string} plainTextPassword such as that provided on a web form
   * @returns {Promise<object>} the user object
   */
  async login(username, plainTextPassword) {
    if (_.isNil(username) || _.isNil(plainTextPassword)) {
      debug('Failed login. Both a username and a password are required.');
      throw  new Error('Invalid credentials.');
    }

    var theUser = null;
    verbose('Beginning login process...');
    let theUser = await this.userDao.one({ username: username });
    if (_.isEmpty(theUser)) {
      throw new UserNotFoundError('Invalid credentials.');
    }
            
    verbose('Attempting password comparison...');
    let isMatch = await bcrypt.compare(plainTextPassword, theUser.password);
    if (isMatch) {
      verbose('Comparison succeeded...');
       if (theUser.must_reset_password) {
        verbose('User must reset password.');
        throw new PasswordExpiredError('Your password has expired and must be reset.');
      }
      //Comparison success, check whether user is valid
      if (theUser.status === 'active') {
        verbose('User resolved successfully.');
        theUser.bad_login_attempts = 0;
        theUser.last_login = moment().utc().format('YYYY-MM-DDTHH:mm:ss');
        theUser.login_count += 1;
        //OK, update the user information, load roles and resolve.
        theUser = await this.userDao.update(theUser);
        let roles = await this.userRoleDao.find({ user_id: theUser.id });
        //Set the roles on the user.
        theUser.roles = roles.map(r => { return r.role; });
        //
        // Success.
        //
        return theUser;

      } else {
        verbose('User has an inactive status.');
        //Any status other than active is considered suspended.
        throw new UserSuspendedError('Your account is no longer active. Please contact your administrator.');
      }
    } else {
      verbose('Password does not match.');
      //Increment bad login attempts and/or flag password reset.
      theUser.bad_login_attempts++;
      var max_bad_logins = opts.max_bad_logins || 10;
      if (theUser.bad_login_attempts >= max_bad_logins) {
        //suspend the user.
        theUser.status = 'suspended';
      }
      verbose('Updating invalid login statistics.');
      await this.userDao.update(theUser);
      throw new InvalidPasswordError('Passwords do not match.');
      
    }
  }
  
  /**
   * Validates a user exists and then generates a reset password token for that user.
   * The user (with the reset_password_token) is then returned via Promise.
   * @param {string} uidString either username or email address.
   */
  async generateResetPasswordToken(uidString) {
    let theUser = await this.userDao.one({ email: uidString });
    if (_.isEmpty(theUser)) {
      theUser = await this.userDao.one({ username: uidString });
    }
    if (_.isEmpty(theUser)) {
      verbose('Requested user was not found.');
      throw new UserNotFoundError('Unable to reset password.');
    }
    //Generate a token.
    theUser.reset_password_token = uuid();
    theUser.reset_password_token_expires = moment().add(1, 'day').utc().format('YYYY-MM-DDTHH:mm:ss');
    verbose('Updating the user with the password reset token which expires at: ' + theUser.reset_password_token_expires);
    theUser = await this.userDao.update(theUser);
    return theUser; //will contain the reset_password_token for use.
         
  }

  /**
    Completes the password-reset process. The new password is hashed and stored, and all
    reset password-related login counters and flags are set to their nominal values.
    @param {string} token the reset-password token issued when the user initially
    requested to reset their password. (Typically this is sent in a validation email as part
    of the reset-password link).
    @param {string} newPlainTextPassword the new user-provided plain-text password
    @returns {Promise<object>} the user object for whom the password was reset. If an
    error occurs, the message returned is NOT suitable for display to the end-user.
  */
  async resetPassword(token, newPlainTextPassword) {
    verbose('Resetting password...')
    //Fetch the user record for the token
    let user = await this.userDao.one({ reset_password_token: token });
    if (_.isEmpty(user)) {
      throw new InvalidResetTokenError();
    }
    //Validate the token.
    var tokenExpiration = moment(user.reset_password_token_expires);
    if (tokenExpiration.isBefore(moment())) {
      throw new ExpiredResetTokenError();
    } else {
      //Salt and hash the password
      verbose('  Hashing password.');
      let hash = await bcrypt.hash(newPlainTextPassword, opts.salt_rounds);
      
      verbose('  Updating user.')
      //Reset counters, clear the token
      user.password = hash;
      user.must_reset_password = false;
      user.reset_password_token = null;
      user.reset_password_token_expires = null;
      user.bad_login_attempts = 0;
      user = await this.userDao.update(user);
      verbose('  ...password reset complete.')
    }
  }

}//AuthService class

exports.AuthService = AuthService;
exports.UserNotFoundError = class UserNotFoundError extends Error { }
exports.UserSuspendedError = class UserSuspendedError extends Error { }
exports.PasswordExpiredError = class PasswordExpiredError extends Error { }
exports.InvalidPasswordError = class InvalidPasswordError extends Error { }
exports.InvalidResetTokenError = class InvalidResetTokenError extends Error { }
exports.ExpiredResetTokenError = class ExpiredResetTokenError extends Error { }