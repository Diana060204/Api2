import express from "express";
import cors  from "cors";
import cookieParser from "cookie-parser";
import usuariosRutas from "./routes/usuarioRutas.js"
import { conectarBD } from "./db/db.js";

async function conexionBD(){
    const respuesta = await conectarBD();
    console.log(respuesta);
    
}
const app = express();
conexionBD();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use("/api",usuariosRutas);

const PORT=process.env.PORT || 3000;
app.listen(PORT, ()=>{
    console.log(`servidor en http://localhost:${PORT}`)
})