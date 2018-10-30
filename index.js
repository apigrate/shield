/**
  Wrapper for handling authentication and route security.
  Makes the base security object available. Adds on two convenience middleware
  functions for routing:
  1. loginRoute - use this to handle POST login requests.
  2. secureFollowingRoutes - place before all routes you need to protect with authentication.

  @param {object} pool a mysql database pool.
  @param {object} opts an options object.
  @example opts
  {
    maxBadLogins: 10,
    saltRounds: 15,
    session_monitor_period: 60,
    db_logger: <winston logger>,
    security_logger: <winston logger>
  }
*/
module.exports=function(pool, opts){
  var winston = require('winston');
  var app = require('express');
  var _ = require('lodash');

  if(!opts) opts = {};
  if(!opts.security_logger){
      opts.security_logger = winston.loggers.get('security');
  }

  var LOGGER = opts.security_logger;

  if(!opts.db_logger){
      opts.db_logger = winston.loggers.get('db');
  }
  var daoFactory = require('./lib/db/database')(pool, opts.db_logger);
  var security = require('./lib/security')(daoFactory, opts);


  /**
    Implements redirecting route-security across an express app. This middleware
    function should be used immediately before all routes that you want to secure.
    Those which should remain public, should be wired BEFORE this is configured
    in app.js.
  */
  security.secureFollowingRoutes = function(req, res, next){
    LOGGER.debug('path is:' + req.path);

    //Check for a session with a user embedded on it.
    //Capture requested url
    var requestedPath = '?rp='+req.path;

    if(_.isEmpty(req.session)){
      LOGGER.silly('No current session.');
      res.redirect('/login'+requestedPath);
    } else if(_.isEmpty(req.session.user)){
      LOGGER.silly('No current user on the session.');
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
  };//middleware fct


  return security;
}
