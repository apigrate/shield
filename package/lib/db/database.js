/**
  Factory for all data access objects.
  Logging will be channeled to a winston logger
  @param {object} pool a mysql database connection pool object is required.
  @param {object} logger (optional) a winston logging instance. If omitted, the
  a default winston logger will be instantiated.
  @returns {object} with data access via Session(), User(), and UserRole() functions.
*/
module.exports=function(pool, logger){
  var _ = require('lodash');
  var winston = require('winston');
  var DBEntity = require('@apigrate/mysqlutils');

  if(!logger) {
    logger = winston.loggers.get('database');
  }

  var factory = {};

  var standard_opts = {
    created_timestamp_column: 'created',
    updated_timestamp_column: 'updated',
    version_number_column: 'version'
  };

  factory.Session = function(){  return _dao('t_session','session', null, require('./session')); }
  factory.User = function(){  return _dao('t_user','user', standard_opts, require('./user')); };
  factory.UserRole = function(){  return _dao('t_user_role','user-role', standard_opts, require('./user-role')); }

  function _dao(table, entity, options, extension){
    var dbe = new DBEntity(table, entity, options, pool, logger);

    if(_.isNil(extension)) return dbe;

    return extension(dbe);
  }

  return factory;
}
