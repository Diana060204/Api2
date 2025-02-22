import mongoose from "mongoose";

const usuariosSchema =new mongoose.Schema({
    username:{
        type:String,
        required:true,
        trim:true,
        unique:true
    },
    email:{
        type:String,
        required:true,
        trim:true,
        unique:true
    },
    password:{
        type:String,
        required:true,
    },
    salt:{
        type:String,
        required:true,
        trim:true,
        unique:true
    }
},
{
   timestamps:true 
});

export default mongoose.model('User', usuariosSchema);