import { mensajes } from './manejoErrores.js'; // Adjust the path as necessary
import jwt from "jsonwebtoken";
import 'dotenv/config';

export function crearToken(dato) {
    return new Promise((resolve, reject) => {
        jwt.sign(
            dato,
            process.env.SECRET_TOKEN,
            { expiresIn: "1h" }, // Set a valid expiration time
            (err, token) => {
                if (err) {
                    reject(mensajes(400, "Error al generar el token"));
                } else {
                    resolve(token);
                }
            }
        );
    });
}