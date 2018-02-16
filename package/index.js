/**
  Wrapper for handling authentication and route security.

  @param {object} pool a mysql database pool.
  @param {object} opts an options object.
  @example opts
  {
    maxBadLogins: 10,
    saltRounds: 15,
    sessionMonitorPeriod: 60,
    db_logger: <winston logger>,
    security_logger: <winston logger>,
    defaultRouteAfterLogin: '/home'
  }
*/
module.exports=function(pool, opts){
  var winston = require('winston');
  var app = require('express');

  if(!opts) opts = {};
  if(!opts.security_logger){
      opts.security_logger = winston.loggers.get('security');
  }
  var LOGGER = opts.security_logger;

  var daoFactory = require('./lib/database')(pool, opts.dblogger);
  var security = require('./lib/security')(daoFactory, opts);


  var service = {};

  /**
    You can use this middleware in your route defintions to handle POST requests to /login
    or implement your own using this as a template.

    On login success:
      The user entity is placed on req.session, if it exists.
      If a req.body.rp (rp=redirect path) is provided, a redirect is issued to that path
      otherwise it will redirect to '/home'.
    On login failure:
      The 'login' view is rendered with the payload:
      {success: false, message: 'Unable to log in.', error: <more detailed error message>}
  */
  service.loginRoute = function(req, res, next){

    return security.login(req.body.username, req.body.password)
    .then(function(user){

      res.locals.user = user;

      if(req.session)
        req.session.user = user;

      if(req.body.rp){
        //if the rp parameer was posted, redirect.
        res.redirect(req.body.rp);
      } else{
        res.redirect(opts.defaultRouteAfterLogin || '/home');
      }
    })

    .catch(function(err){
      LOGGER.error('Login failure. Details: ' + err.message);
      res.render('login', {success: false, message: 'Unable to log in.', error: err.message});
    })

  };//loginRoute

  /**
    Implements redirecting route-security across an express app. This middleware
    function should be used immediately before all routes that you want to secure.
    Those which should remain public, should be wired BEFORE this is configured
    in app.js.
  */
  service.secureRoutesAfter = function(req, res, next){
    LOGGER.debug('path is:' + req.path);

    //Check for a session with a user embedded on it.
    //Capture requested url
    var requestedPath = '?rp='+req.path;

    if(_.isNil(req.session)|| _.isNil(req.session.user)){
      LOGGER.silly('No current session.');
      res.redirect('/login'+requestedPath);
    } else {
      LOGGER.silly('Validating session...');
      if(req.session.user.status==='active'){
        LOGGER.silly('Current user is active...');
        next();
      } else {
        res.redirect('/login'+requestedPath);
      }

    }


  }//middleware fct
}
