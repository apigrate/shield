module.exports = function(UserRole){

  UserRole.getRolesForUser = function(userId){
    return UserRole.find({user_id: userId});
  }
  return UserRole;
}
