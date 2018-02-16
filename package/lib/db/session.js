module.exports=function(Session){

  Session.getForUser = function(user){
    return Session.find({user_id: user.id});
  }

  Session.deleteWhereExpired = function(){
    return Session.deleteWhere('expires < CURRENT_TIMESTAMP');
  }

  return Session;
}
