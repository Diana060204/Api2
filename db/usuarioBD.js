import User from "../models/usuarioModelo.js";
import { encriptarPassword, validarPassword } from "../middlewares/funcionesPassword.js";
import { mensajes } from "../libs/manejoErrores.js";
import { crearToken } from "../libs/jwt.js";
export async function register ({username, email, password}){
    try {
        const usuarioExistente = await User.findOne({username});
       
        if(usuarioExistente){
            return mensajes(400, "Usuario ya existente");
        }
        const emailExistente = await User.findOne({email});
        if(emailExistente){
            return mensajes(400, "Email ya existente");
        }
       
        const {hash, salt} = encriptarPassword(password);
    const data = new User({username, email, password:hash, salt});
    //console.log(data);
    
   var respuesta= await data.save();
   const token = await crearToken({id:respuesta._id});
   return mensajes(200, "Registro agregado ---- ", "",token);
    } catch (error) {
        return mensajes(400, error);
}
}

export const login = async ({username, password}) => {
    try {
        const usuarioCorrecto = await User.findOne({username});
        if(!usuarioCorrecto){
            return mensajes(400, "Datos incorrectos");
        }
        const passwordCorrecto = validarPassword(password, usuarioCorrecto.salt, usuarioCorrecto.password);
        if(!passwordCorrecto){
            return mensajes(400, "Datos incorrectos");
        }
        
        const token = await crearToken({id: usuarioCorrecto._id}); // Generate token
        return mensajes(200, "Acceso Permitido", "", token); // Return token in response
    } catch (error) {
        return mensajes(400, "Datos incorrectos");
    }
}