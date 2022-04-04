import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import {repository} from '@loopback/repository';
import {PersonaRepository, UsuarioRepository} from '../repositories';
import {Usuario} from '../models/usuario.model';
import {Llaves} from '../config/Llaves';
const generador = require('password-generator');
const cryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(
    @repository(PersonaRepository)
    public personaRepository: PersonaRepository,
    @repository(UsuarioRepository)
    public usuarioRepository: UsuarioRepository,
  ) {}

  /*
   * Add service methods here
   */

  GenerarClave() {
    let clave = generador(8, false);
    return clave;
  }

  CifrarClave(clave: string) {
    let claveCifrada = cryptoJS.MD5(clave).toString();
    return claveCifrada;
  }

  IdentificarPersona(documento: string) {
    try {
      let p = this.personaRepository.findOne({where: {documento: documento}});
      if (p) {
        return p;
      }
      return false;
    } catch {
      return false;
    }
  }

  IdentificarUsuario(usuario: string, clave: string) {
    
    try {
      let p = this.usuarioRepository.findOne({
        where: {correo: usuario, clave: clave},
      });
      if (p) {
        return p;
      }
      return false;
    } catch {
      return false;
    }
  }

  GenerarTokenJWT(usuario: Usuario) {
    let token = jwt.sign(
      {
        data: {
          id: usuario.id,
          correo: usuario.correo,
          nombres: usuario.nombre + ' ' + usuario.apellido,
          rol: usuario.rol,
        },
      },
      Llaves.claveJWT,
    );
    return token;
  }

  ValidarTokenJWT(token: string) {
    try {
      let datos = jwt.verify(token, Llaves.claveJWT);
      return datos;
    } catch {
      return false;
    }
  }
}
