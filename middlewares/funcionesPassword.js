import crypto from "crypto";
import jwt from "jsonwebtoken";
import "dotenv/config";

export function encriptarPassword(password) {
    const salt = crypto.randomBytes(32).toString("hex");
    const hash = crypto.scryptSync(password, salt, 10, 64, "sha512").toString("hex");
    return {
        salt,
        hash
    };
}

export function validarPassword(password, salt, hash) {
    const hashEvaluar = crypto.scryptSync(password, salt, 10, 64, "sha512").toString("hex");
    return hashEvaluar === hash; // Use strict equality
}

export function usuarioAutorizado(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(400).json("Usuario no autorizado"); // Return response
    }
    jwt.verify(token, process.env.SECRET_TOKEN, (error, usuario) => {
        if (error) {
            return res.status(400).json("Usuario no autorizado"); // Return response
        }
        console.log(usuario);
        req.usuario = usuario;
        next(); // Call next() here to continue to the next middleware
    });
}

export function adminAutorizado(req, res, next) {
    // Verifica si el usuario está autenticado y si su tipo de usuario es 'admin'
    if (!req.usuario || req.usuario.tipoUsuario !== 'admin') {
        return res.status(403).json("Acceso denegado. Solo los administradores pueden realizar esta acción.");
    }
    next(); // Si es un administrador, continúa con la siguiente función middleware
}