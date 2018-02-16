# shield
A mysql-based authentication implementation for Express apps.


## Functions

Four  functions are implemented:
1. login
1. generateResetPasswordToken
1. resetPassword
1. secureFollowingRoutes

### function: login
The `login` is a promise-returning function accepting a username and password. The password is compared to a hashed and salted password stored in the database. Upon success, a promise bearing the user object user is returned to the next function; otherwise an error is returned with a message that is reasonable to be displayed to the end-user (i.e. does not disclose whether a username or the password was incorrect, only that the login was invalid).

### function: generateResetPasswordToken
The `generateResetPasswordToken` is a promise-returning function accepting a username. It generates a password reset token that is valid for 1 day (TODO: make this configurable). The token is returned on returned user object. If an invalid or unknown user id is used, an error is returned. Use this function to implement password-reset-by-link capabilities in your app.

### function: resetPassword
The `resetPassword` is a promise-returning function accepting a password-reset token and two password parameters. It validates that a user is assigned the given token, that the token has not expired, and that the two plaintext password parameters match. Upon successful validation, the user is updated and returned; otherwise an error is returned.

### function: secureFollowingRoutes
The `secureFollowingRoutes` function is an ExpressJS middleware function. Include it in your application routing configuration immediately before all routes you wish to secure.

This function will block access to following routes and redirect the user to a `/login` path when:
1. the `req.session` is empty, or
1. the `req.session.user` is empty, or
1. the `req.session.user.status !== 'active'`

Otherwise, the request is allowed to pass to the requested resource.

Note: the originally requested path is provided on the redirect url in the `rp` query parameter. For example, if the user requested access to `/cats_and_dogs`, but was redirected to login, the redirect invocation would be `/login?rp=/cats_and_dogs`. In this way you can choose to conveniently redirect your users to the originally-requested-resource AFTER they login.

## Database Tables
The following database tables are required for persisting user and role information. (Currently user role functionality is a future consideration.) A create script is also available at `./lib/db/create-tables.sql`.
```sql
-- Create for TABLE 't_user'
CREATE TABLE `t_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `first_name` varchar(255) NOT NULL,
  `last_name` varchar(255) NOT NULL,
  `mobile_phone` varchar(20) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `status` varchar(20) DEFAULT NULL,
  `must_reset_password` tinyint(3) unsigned NOT NULL DEFAULT '0',
  `bad_login_attempts` int(11) NOT NULL DEFAULT '0',
  `last_login` timestamp NULL DEFAULT NULL,
  `login_count` int(11) NOT NULL DEFAULT '0',
  `reset_password_token` varchar(255) DEFAULT NULL,
  `reset_password_token_expires` timestamp NULL DEFAULT NULL,
  `default_org_id` int(11) DEFAULT NULL,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `version` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username_UNIQUE` (`username`),
  UNIQUE KEY `email_UNIQUE` (`email`),
  FULLTEXT KEY `username` (`username`,`first_name`,`last_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- Create for TABLE 't_user_role'
CREATE TABLE `t_user_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `role` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

## Examples

***A note aboute session management***: This library is unopinionated with regard to session management. We have had good success with  `express-session` and `express-mysql-sesssion`.

### A login route example.
Here is a sample implementation for a login route function, involving sessions. In this example the `Shield` library is assumed to have been made available at `app.locals` in your global configuration script (typically `app.js`).

```javascript
/**
  Handle a user login.
*/
router.post('/login', function(req, res, next){

  return req.app.locals.Shield.login(req.body.username, req.body.password)
  .then(function(user){

    res.locals.user = user;
    req.session.user = user;

    //Now save the session.
    req.session.save(function(err) {
      if(err) throw err;

      //Saved ok
      if(req.body.rp){
        //if the rp parameter was posted, redirect.
        res.redirect(req.body.rp);
      } else{
        res.redirect('/');//or whatever your 'home' route is.
      }
    });

  })
  .catch(function(err){
    res.render('login', {error: 'Unable to log in.'});
  });

});
```


### A forgot password route example.
This is a sample implementation for a 'forgot password' route. In this example we assume that we have been presented with a POST from a form where the user entered their username.
```javascript
/**
  Receives POST containing the username of the user who is requesting
  a password reset. This process validates the user and then generates a
  reset password token, emailing the user a link.

  The link will point to another route (not shown here) where they
  will complete the process.
*/
router.post('/password-request-reset', function(req, res) {

  //Your route to display the actual password reset options
  var linkbase = req.protocol + '://' + req.get('host') + '/password/reset';

  var message = null;

  //Assumed to be avaliable from global config.
  req.app.locals.Shield.generateResetPasswordToken(req.body.username)
  .then(function(user){

    //The username was valid.

    var emailService = require('an email service');

    var emailContent = `Dear ${user.first_name},\n\
    We received password-reset request for your account. You may complete the password reset process by clicking the link below.\n\
    ${linkbase}?token=${user.reset_password_token}\n\
    If you did not make this request, ignore the link and contact us if you have any questions.`;

    emailService.sendEmail(emailContent, etc.);

    message = 'An email containing instructions to reset your password has been sent.';
    return Promise.resolve();
  })
  .catch(function(err){
    message = 'We are unable to reset your password at this time. Try again later or contact your administrator.';
    return Promise.resolve();
  })
  .then(function(){
    //In our example, all roads lead to rendering this view,
    // with an appropriate message.
    res.render('forgot-password', {message: message});
  });

});

```
