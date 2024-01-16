# Importando paquetes desde Flask
from flask import session, flash

# Importando conexión a BD
from conexion.conexionBD import connectionBD
# Para validar contraseña
from werkzeug.security import check_password_hash

import re
# Para encriptar contraseña generate_password_hash
from werkzeug.security import generate_password_hash


# Función para recibir e insertar un nuevo registro de usuario
def recibeInsertRegisterUser(cedula, name, surname, id_area, f_ingreso_usuario, id_rol, pass_user):
    # Validar la data antes de realizar la inserción
    respuestaValidar = validarDataRegisterLogin(cedula, name, surname, pass_user)

    if respuestaValidar:
        # Generar hash de la nueva contraseña
        nueva_password = generate_password_hash(pass_user, method='scrypt')
        try:
            with connectionBD() as conexion_MySQLdb:
                with conexion_MySQLdb.cursor(dictionary=True) as mycursor:
                    # Realizar la inserción en la base de datos
                    sql = """
                    INSERT INTO usuarios(cedula, nombre_usuario, apellido_usuario, id_area, f_ingreso, id_rol, password) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """
                    valores = (cedula, name, surname, id_area, f_ingreso_usuario, id_rol, nueva_password)
                    mycursor.execute(sql, valores)
                    conexion_MySQLdb.commit()
                    resultado_insert = mycursor.rowcount
                    return resultado_insert
        except Exception as e:
            # Manejar errores durante la inserción
            print(f"Error en el Insert users: {e}")
            return []
    else:
        # Informar al usuario si la validación no es exitosa
        return False


# Función para validar la data del registro antes de realizar el login
def validarDataRegisterLogin(cedula, name, surname, pass_user):
    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                querySQL = "SELECT * FROM usuarios WHERE cedula = %s"
                cursor.execute(querySQL, (cedula,))
                userBD = cursor.fetchone()

                # Verificar si ya existe un usuario con la misma cédula
                if userBD is not None:
                    flash('El registro no fue procesado. Ya existe la cuenta.', 'error')
                    return False
                # Verificar si algún campo requerido está vacío
                elif not cedula or not name or not pass_user or not surname:
                    flash('Por favor llene los campos del formulario.', 'error')
                    return False
                else:
                    # La cuenta no existe y los datos del formulario son válidos
                    return True
    except Exception as e:
        # Manejar errores durante la validación
        print(f"Error en validarDataRegisterLogin : {e}")
        return []


# Función para obtener la información de perfil de un usuario
def info_perfil_session(id):
    print(id)
    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                querySQL = "SELECT id_usuario, nombre_usuario, apellido_usuario, cedula, id_area, f_ingreso, id_rol FROM usuarios WHERE id_usuario = %s"
                cursor.execute(querySQL, (id,))
                info_perfil = cursor.fetchall()
        return info_perfil
    except Exception as e:
        # Manejar errores al obtener la información del perfil
        print(f"Error en info_perfil_session : {e}")
        return []

# Función para procesar la actualización del perfil de un usuario
def procesar_update_perfil(data_form, id):
    # Extraer datos del formulario
    id_user = id
    cedula = data_form['cedula']
    nombre_usuario = data_form['name']
    apellido_usuario = data_form['surname']
    id_area = data_form['selectArea']
    f_ingreso = data_form['f_ingreso_usuario']
    id_rol = data_form['selectRol']
    new_pass_user = data_form['new_pass_user']
    
    # Verificar si el usuario tiene el rol 1 (puedes usar una constante en lugar de 1)
    if session['rol'] == 1:
        try:
            # Generar hash de la nueva contraseña
            nueva_password = generate_password_hash(new_pass_user, method='scrypt')
            with connectionBD() as conexion_MySQLdb:
                with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                    # Realizar la actualización del perfil
                    querySQL = """
                        UPDATE usuarios
                        SET 
                            nombre_usuario = %s,
                            apellido_usuario = %s,
                            id_area = %s,
                            f_ingreso = %s,
                            id_rol = %s,
                            password = %s
                        WHERE id_usuario = %s
                    """
                    params = (nombre_usuario, apellido_usuario, id_area, f_ingreso, id_rol,
                              nueva_password, id_user)
                    cursor.execute(querySQL, params)
                    conexion_MySQLdb.commit()
            return 1
        except Exception as e:
            # Manejar errores durante la actualización del perfil
            print(f"Ocurrió en procesar_update_perfil: {e}")
            return []

    # Verificar si el usuario no desea cambiar la contraseña
    if not pass_actual and not new_pass_user and not repetir_pass_user:
        return updatePefilSinPass(id_user, nombre_usuario, apellido_usuario, id_area,f_ingreso, id_rol)

    pass_actual = data_form['pass_actual']
    repetir_pass_user = data_form['repetir_pass_user']
    # Verificar la contraseña actual antes de realizar la actualización
    with connectionBD() as conexion_MySQLdb:
        with conexion_MySQLdb.cursor(dictionary=True) as cursor:
            querySQL = """SELECT * FROM usuarios WHERE cedula = %s LIMIT 1"""
            cursor.execute(querySQL, (cedula,))
            account = cursor.fetchone()
            if account:
                if check_password_hash(account['password'], pass_actual):
                    # Verificar si las nuevas contraseñas coinciden
                    if new_pass_user != repetir_pass_user:
                        return 2  # Indicar que las contraseñas no coinciden
                    else:
                        try:
                            # Generar hash de la nueva contraseña
                            nueva_password = generate_password_hash(new_pass_user, method='scrypt')
                            with connectionBD() as conexion_MySQLdb:
                                with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                                    # Realizar la actualización del perfil
                                    querySQL = """
                                        UPDATE usuarios
                                        SET 
                                            nombre_usuario = %s,
                                            apellido_usuario = %s,
                                            id_area = %s,
                                            f_ingreso = %s,
                                            id_rol = %s,
                                            password = %s
                                        WHERE id_usuario = %s
                                    """
                                    params = (nombre_usuario, apellido_usuario, id_area, f_ingreso, id_rol,
                                              nueva_password, id_user)
                                    cursor.execute(querySQL, params)
                                    conexion_MySQLdb.commit()
                            return cursor.rowcount or []
                        except Exception as e:
                            # Manejar errores durante la actualización del perfil
                            print(f"Ocurrió en procesar_update_perfil: {e}")
                            return []
            else:
                print("Contraseñas no coinciden")
                return 0  # Indicar que el usuario no existe


# Función para actualizar el perfil sin cambiar la contraseña
def updatePefilSinPass(id_user, nombre_usuario, apellido_usuario, id_area, f_ingreso, id_rol):
    try:
        with connectionBD() as conexion_MySQLdb:
            with conexion_MySQLdb.cursor(dictionary=True) as cursor:
                # Realizar la actualización del perfil sin cambiar la contraseña
                querySQL = """
                    UPDATE usuarios
                    SET 
                        nombre_usuario = %s,
                        apellido_usuario = %s,
                        id_area = %s,
                        f_ingreso = %s,
                        id_rol = %s
                    WHERE id_usuario = %s
                """
                params = (nombre_usuario, apellido_usuario, id_area, f_ingreso, id_rol, id_user)
                cursor.execute(querySQL, params)
                conexion_MySQLdb.commit()
        return cursor.rowcount
    except Exception as e:
        # Manejar errores durante la actualización del perfil sin cambiar la contraseña
        print(f"Ocurrió un error en la funcion updatePefilSinPass: {e}")
        return []


# Función para obtener la información de login de la sesión actual
def dataLoginSesion():
    inforLogin = {
        "id": session['id'],
        "name": session['name'],
        "cedula": session['cedula'],
        "rol": session['rol']
    }
    return inforLogin
