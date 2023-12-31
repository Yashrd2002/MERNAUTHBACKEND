const { Timestamp } = require("mongodb");
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      unique: true,
    },
    password: String,
  },
  { Timestamp: true }
);

const UserModel = mongoose.model('User',UserSchema)
module.exports = UserModel;