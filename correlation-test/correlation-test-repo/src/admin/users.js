function getUser(db, name) {
  return db.query("SELECT * FROM admins WHERE name = '" + name + "'");
}
module.exports = { getUser };
