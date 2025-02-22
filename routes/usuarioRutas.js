import { Router } from "express";
import { register, login } from "../db/usuarioBD.js";
import User from "../models/usuarioModelo.js";
import { mensajes } from "../libs/manejoErrores.js";
import bcrypt from 'bcrypt'; // Asegúrate de tener bcrypt instalado

const router = Router();

// Middleware para verificar si el usuario es administrador
const verificarAdmin = async (req, res, next) => {
    const { id } = req.params; // Suponiendo que el ID del usuario está en los parámetros
    const usuario = await User.findById(id);
    if (!usuario || usuario.tipoUsuario !== 'admin') {
        return res.status(403).json({ mensaje: "Acceso denegado. Solo un administrador puede realizar esta acción." });
    }
    next();
};

// Registro de usuarios
router.post("/registro", async (req, res) => {
    const respuesta = await register(req.body);
    res.cookie('token', respuesta.token).status(respuesta.status).json(respuesta);
});

// Inicio de sesión
router.post("/login", async (req, res) => {
    const respuesta = await login(req.body);
    res.cookie('token', respuesta.token).status(respuesta.status).json(respuesta);
});

// Ruta para salir
router.get("/salir", async (req, res) => {
    res.send("Estas en Salir");
});

// Mostrar todos los usuarios
router.get("/usuarios", async (req, res) => {
    try {
        const usuarios = await User.find();
        res.status(200).json(usuarios);
    } catch (error) {
        res.status(500).json({ mensaje: "Error al obtener usuarios", error });
    }
});

// Buscar usuario por ID
router.get("/usuarios/:id", async (req, res) => {
    const { id } = req.params;
    if (!id) {
        return res.status(400).json({ mensaje: "ID de usuario es requerido" });
    }
    try {
        const usuario = await User.findById(id);
        if (!usuario) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }
        res.status(200).json(usuario);
    } catch (error) {
        res.status(500).json({ mensaje: "Error al buscar usuario", error });
    }
});

// Borrar usuario por ID
router.delete("/usuarios/:id", async (req, res) => {
    const { id } = req.params;
    if (!id) {
        return res.status(400).json({ mensaje: "ID de usuario es requerido" });
    }
    try {
        const usuarioBorrado = await User.findByIdAndDelete(id);
        if (!usuarioBorrado) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }
        res.status(200).json({ mensaje: "Usuario borrado correctamente", usuario: usuarioBorrado });
    } catch (error) {
        res.status(500).json({ mensaje: "Error al borrar usuario", error });
    }
});

// Actualizar usuario por ID
router.put("/usuarios/:id", async (req, res) => {
    const { id } = req.params;
    if (!id) {
        return res.status(400).json({ mensaje: "ID de usuario es requerido" });
    }
    if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ mensaje: "Datos para actualizar son requeridos" });
    }
    try {
        const usuarioActualizado = await User.findByIdAndUpdate(id, req.body, { new: true });
        if (!usuarioActualizado) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }
        res.status(200).json({ mensaje: "Usuario actualizado correctamente", usuario: usuarioActualizado });
    } catch (error) {
        res.status(500).json({ mensaje: "Error al actualizar usuario", error });
    }
});

// Cambiar tipo de usuario
router.put("/usuarios/:id/cambiarTipoUsuario", async (req, res) => {
    const { id } = req.params;
    try {
        const usuario = await User.findById(id);
        if (!usuario) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }
        
        // Cambiar tipo de usuario
        usuario.tipoUsuario = usuario.tipoUsuario === 'admin' ? 'usuario' : 'admin';
        
        // Verificar si el tipo de usuario está vacío después de cambiarlo
        if (!usuario.tipoUsuario || usuario.tipoUsuario === "") {
            return res.status(400).json({ mensaje: "Error al cambiar tipo de usuario. El tipo de usuario no puede estar vacío." });
        }

        await usuario.save();
        res.status(200).json({ mensaje: "Tipo de usuario cambiado correctamente", usuario });
    } catch (error) {
        res.status(500).json({ mensaje: "Error al cambiar tipo de usuario", error });
    }
});
// Cambiar contraseña
router.put("/usuarios/:id/cambiarPassword", async (req, res) => {
    const { id } = req.params;
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ mensaje: "La nueva contraseña es requerida" });
    }
    try {
        const usuario = await User.findById(id);
        if (!usuario) {
            return res.status(404).json({ mensaje: "Usuario no encontrado" });
        }
        // Encriptar la nueva contraseña
        const salt = await bcrypt.genSalt(10);
        usuario.password = await bcrypt.hash(password, salt);
        await usuario.save();
        res.status(200).json({ mensaje: "Contraseña cambiada correctamente" });
    } catch (error) {
        res.status(500).json({ mensaje: "Error al cambiar la contraseña", error });
    }
});

export default router;