#!/usr/bin/python
# -*- coding: utf-8 -*-
# Diego Martín Sánchez, 2º ASIR

import ldap
import ldap.modlist as modlist
import getpass
import json

# Comprueba las credenciales de acceso al servidor LDAP
def comprobar_conexion(usuario, passwd, server, base):
    try:
        server.protocol_version = ldap.VERSION3
        server.simple_bind_s(usuario,passwd)
    except ldap.INVALID_CREDENTIALS:
        print "Error en las credenciales de acceso al servidor LDAP."
        exit()

# Extrae el cuerpo de la clave pública para luego almacenarlo en el LDAP
def extraer_clave(pubkey):
    elementos = pubkey.split(" ")
    numelementos = len(elementos)
    if (numelementos == 2 and elementos[0] == "ssh-rsa") or numelementos == 3:
        clave = elementos[1]
    else:
        clave = elementos[0]
    return clave

# Credenciales de acceso al servidor LDAP
server = 'ldap://piolin.diego.gonzalonazareno.org:389'
base = 'dc=diego,dc=gonzalonazareno,dc=org'
username =('cn=admin,%s'%base)
password = getpass.getpass(' Introduce la contraseña del usuario "%s": '%username)

# Cargamos el fichero JSON
fichero = open('usuarios.json')
usuarios = json.load(fichero)
fichero.close

# Establece la conexión con el servidor LDAP
serverldap = ldap.initialize(server)
comprobar_conexion(username, password,serverldap, base)
serverldap.simple_bind(username, password)

# Recorre el fichero JSON
identificador = 2001
for usuario in usuarios['humanos']:
    # Almacena la infomación de cada usuario
    dn = ('uid=%s,ou=people,%s'%(usuario['usuario'], base))
    atributos = {}
    atributos['objectclass'] = ['top','posixAccount','person','organizationalPerson','inetOrgPerson','ldapPublicKey']
    atributos['cn'] = usuario['usuario'].encode('utf-8','ignore')
    atributos['uid'] = usuario['usuario'].encode('utf-8','ignore')
    atributos['givenName'] = usuario['nombre'].encode('utf-8','ignore')
    atributos['sn'] = usuario['apellidos'].encode('utf-8','ignore')
    atributos['uidNumber'] = str(identificador)
    atributos['gidNumber'] = '2000'
    atributos['homeDirectory'] = ('/home/%s'%usuario['usuario'].encode('utf-8','ignore'))
    atributos['loginShell'] = '/bin/bash'
    atributos['mail'] = usuario['correo'].encode('utf-8','ignore')
    atributos['sshPublicKey'] = extraer_clave(usuario['clave'].encode('utf-8','ignore'))
    identificador = identificador + 1
    # Convierte el diccionario en una lista de truplas
    atributos = modlist.addModlist(atributos)
    # Añade el nuevo usuario al árbol
    serverldap.add(dn, atributos)
# Cierre de conexión    
serverldap.unbind()
