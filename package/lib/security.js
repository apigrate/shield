/**
  Various security-related core services for use within the app.
  @param {object} daoFactory data access object factory (see ./db/database)
  @param {object} options object for controlling logins, session cleanup, encryption strength
  @example {
    maxBadLogins: 10,
    saltRounds: 15,
    sessionMonitorPeriod: 60,
    security_logger: <winston logger>
  }
  @module security
*/
module.exports=function(daoFactory, opts){
  var security = {};
  if(!opts){
    opts = {};
  }
  var _ = require('lodash');
  var moment = require('moment');
  var uuid = require('uuid');
  var bcrypt = require('bcryptjs');

  var User = daoFactory.User();
  var UserRole = daoFactory.UserRole();
  var Session = daoFactory.Session();

  var LOGGER = opts.security_logger || require('winston');

  class UserNotFoundError extends Error{}
  class UserSuspendedError extends Error{}
  class PasswordExpiredError extends Error{}
  class InvalidPasswordError extends Error{}
  class InvalidResetTokenError extends Error{}
  class ExpiredResetTokenError extends Error{}
  /**
    Logs in a user. Password is compared against the hash stored in the database.
    @return a promise bearing the user, if login is successful, otherwise an
    error message is returned that is suitable for display to the end-user.
  */
  function login(username, plainTextPassword){

    return new Promise(function(resolve, reject){

      var theUser = null;

      LOGGER.silly('Beginning login process...');
      return User.one({username: username})
      .then(function(user){
        if(_.isNil(user)){
          throw new UserNotFoundError('No user found.' );
        } else if (user.status==='suspended'){
          LOGGER.silly('User status=suspended.');
          throw new UserSuspendedError('Your account has been suspended. Please contact your administrator.');
        } else if (user.must_reset_password){
          LOGGER.silly('User must reset password.');
          throw new PasswordExpiredError('Your password has expired and must be reset.');
        } else {
          theUser = user;
          LOGGER.silly('Attempting password comparison...');
          return bcrypt.compare(plainTextPassword, theUser.password);
        }
      })
      .then(function(compareResult){
        if(compareResult){
          LOGGER.silly('Comparison succeeded...');
          //Comparison success, check whether user is valid
          if(theUser.status==='active'){

            LOGGER.silly('User resolved successfully.');

            theUser.bad_login_attempts = 0;
            theUser.last_login = moment().utc().format('YYYY-MM-DDTHH:mm:ss');
            theUser.login_count += 1;
            //OK, update the user information, load roles and resolve.
            return User.update(theUser)
            .then(function(userAfter){
              return UserRole.getRolesForUser(userAfter.id);
            })
            .then(function(roles){
              //Set the roles on the user.
              theUser.roles = [];
              _.each(roles, function(r){
                theUser.roles.push(r.role);
              });

              resolve(theUser);
            });

          } else {
            LOGGER.silly('User has an inactive or invalid status.');
            //Any status other than active is considered suspended.
            reject(new UserSuspendedError('Your account has been suspended. Please contact your administrator.'));
          }
        } else {
          LOGGER.silly('Comparison failed.');
          //Increment bad login attempts and/or flag password reset.
          theUser.bad_login_attempts++;
          var maxBadLogins = opts.maxBadLogins || 10;
          if(theUser.bad_login_attempts >= maxBadLogins){
            //suspend the user.
            theUser.status='suspended';
          }
          LOGGER.silly('Updating invalid login statistics.');
          return User.update(theUser)
          .catch(function(err){
            throw( new Error( 'Unable to record invalid login for user '+theUser.username+'. Details: ' + err.message ) );
          })
          .then(function(){
            throw( new InvalidPasswordError( 'Passwords do not match.') );
          });
        }
      })
      .catch(function(err){
        //Some types of error should be generic to disguise the cause from miscreants.
        if(err instanceof UserNotFoundError){
          reject(new Error ('Invalid login.'));
        } else if (err instanceof UserSuspendedError){
          reject(err);
        } else if (err instanceof PasswordExpiredError){
          reject(err);
        } else if (err instanceof InvalidPasswordError){
          reject(new Error ('Invalid login.'));
        } else {
          LOGGER.warn('Login processing error: '  + err.message);
          reject(new Error ('Invalid login.'));
        }

      });
    });
  }

  /**
    Validates a user exists and then generates a reset password token for that user.
    The user (with the reset_password_token) is then returned via Promise.

    @param {string} uidString
    @returns {Promise<User>} the promise bearing the user object with a reset_password_token.
  */
  function generateResetPasswordToken(uidString, communicatePasswordReset){
    return new Promise(function(resolve, reject){
      var theUser = null;
      //Lookup user by email.
      User.getByEmail(uidString)
      .then(function(user){
        if(_.isEmpty(user)){
          //Try looking up by username
          return User.getByUsername(uidString)
        } else {
          return Promise.resolve(user);
        }
      })
      .then(function(user){
        if(_.isEmpty(user)){
          LOGGER.silly('Requested user was not found.');
          reject(new UserNotFoundError('Unable to reset password.'));
        }
        theUser = user;
        //Generate a token.
        theUser.reset_password_token=uuid();
        theUser.reset_password_token_expires=moment().add(1, 'day').utc().format('YYYY-MM-DDTHH:mm:ss');
        LOGGER.silly('Updating the user with the password reset token which expires at: ' + theUser.reset_password_token_expires);
        return User.update(theUser);
      })
      .then(function(user){
        resolve(user);//will contain the reset_password_token for use.
      })
      .catch(function(err){
      	reject(err);
      });
    });

  }

  /**
    Completes the password-reset process. The new password is hashed and stored, and all
    reset password-related login counters and flags are set to their nominal values.
    @param {string} token the reset-password token issued when the user initially
    requested to reset their password. (Typically this is sent in a validation email as part
    of the reset-password link).
    @param {string} newPlainTextPassword the new user-provided plain-text password
    @returns a promise bearing the user object for whom the password was reset. If an
    error occurs, the message returned is NOT suitable for display to the end-user.
  */
  function resetPassword(token, newPlainTextPassword){
    return new Promise(function(resolve, reject){
      LOGGER.silly('Resetting password...')
      //Fetch the user record for the token
      User.getByPasswordResetToken(token)
      .then(function(user){
        if(_.isEmpty(user)){
          reject(new InvalidResetTokenError());
        } else {
          //Validate the token.
          var tokenExpiration = moment(user.reset_password_token_expires);
          if(tokenExpiration.isBefore(moment())){
            reject(new ExpiredResetTokenError());
          } else{
            //Salt and hash the password
            LOGGER.silly('  Hashing password.');
            bcrypt.hash(newPlainTextPassword, opts.saltRounds, function(err, hash) {
              LOGGER.silly('  Updating user.')
              //Reset counters, clear the token
              user.password = hash;
              user.must_reset_password = false;
              user.reset_password_token = null;
              user.reset_password_token_expires = null;
              user.bad_login_attempts = 0;
              return User.update(user);
            });
          }
        }
      })
      .then(function(user){
        LOGGER.silly('  ...password reset complete.')
        resolve(user);
      })
      .catch(function(err){
        reject(err);
      });

    });

  }


  /**
    Function that starts a periodic process which removes expired user sessions
    from the database. To control the polling period, set the
    {opts.sessionMonitorPeriod} property to an appropriate value in seconds
    (defaults to 60s);
  */
  function reapExpiredSessions(){
    setInterval(function(){
      Session.deleteWhereExpired()
      .then(function(result){
        LOGGER.info( result._affectedRows +' expired sessions were removed.')
      })
      .catch(function(err){
        LOGGER.error('Error removing expired sessions. Details:');
        LOGGER.error(err);
      });
    }, (opts.sessionMonitorPeriod*1000) || 60000 );
  }

  /** Logs in a user @see login by adding a session to the database. */
  security.login = login;

  /** Logs out a user by removing his session from the database. */
  security.logout = logout;

  /** Resets a users password and clears any reset password related counters. */
  security.resetPassword = resetPassword;

  /** For a given user id, validate the user and return the user with a reset password token to be used for that process */
  security.generateResetPasswordToken = generateResetPasswordToken;

  /** A polling process that removes expired sessions.*/
  security.reapExpiredSessions = reapExpiredSessions;

  return security;
}
