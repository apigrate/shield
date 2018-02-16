module.exports=function(User){

  User.getByUsername = function(username){
    return User.one({username: username});
  }

  User.getByPasswordResetToken = function(token){
    return User.one({reset_password_token: token});
  }

  User.getUsersForOrg = function(orgId){
    return User.one({reset_password_token: token});
  }

  User.getByEmail = function(email){
    return User.one({email: email});
  }

  return User;
}
