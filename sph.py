# app.py
# Requisitos: pip install streamlit pandas pyzbar pillow openpyxl werkzeug

import streamlit as st
import sqlite3
import pandas as pd
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import io
import re

# ---------- Base de datos SQLite con WAL y synchronous NORMAL ----------
@st.cache_resource
def init_sqlite():
    conn = sqlite3.connect('event.db', check_same_thread=False)
    c = conn.cursor()
    # Habilitar Write-Ahead Logging para concurrencia mejorada
    c.execute("PRAGMA journal_mode=WAL;")
    # Ajustar sincronización para balance rendimiento/seguridad
    c.execute("PRAGMA synchronous=NORMAL;")
    # Tabla de usuarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    # Tabla de registros de ingreso
    c.execute('''
        CREATE TABLE IF NOT EXISTS entries (
            timestamp TEXT,
            username TEXT,
            cedula TEXT,
            extra TEXT
        )
    ''')
    # Reconstruir esquema de event_data
    c.execute('DROP TABLE IF EXISTS event_data')
    c.execute('''
        CREATE TABLE event_data (
            cedula TEXT PRIMARY KEY,
            nombre TEXT,
            mesa TEXT
        )
    ''')
    conn.commit()
    # Crear usuario admin por defecto
    c.execute('SELECT 1 FROM users WHERE username=?', ('admin',))
    if not c.fetchone():
        c.execute('INSERT INTO users VALUES (?, ?)',
                  ('admin', generate_password_hash('admin')))
        conn.commit()
    return conn

conn = init_sqlite()
c = conn.cursor()

# ---------- Funciones de autenticación ----------
def register_user(username, password):
    hashed = generate_password_hash(password)
    try:
        c.execute('INSERT INTO users VALUES (?, ?)', (username, hashed))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def login_user(username, password):
    c.execute('SELECT password FROM users WHERE username=?', (username,))
    row = c.fetchone()
    return bool(row and check_password_hash(row[0], password))

# ---------- Procesar QR ----------
def process_qr():
    data = st.session_state.qr_input.strip()
    m = re.match(r'^(?P<cedula>\d+)(?:\\(?P<extra>.*))?$', data)
    if m:
        cedula = m.group('cedula')
        extra = m.group('extra') or ''
    else:
        cedula, extra = data, ''
    prev_count = c.execute('SELECT COUNT(*) FROM entries WHERE cedula=?', (cedula,)).fetchone()[0]
    if prev_count > 0:
        ts_prev = c.execute(
            'SELECT timestamp FROM entries WHERE cedula=? ORDER BY timestamp ASC LIMIT 1',
            (cedula,)
        ).fetchone()[0]
        st.session_state.qr_result = ('duplicate', ts_prev)
    else:
        c.execute('SELECT nombre, mesa FROM event_data WHERE cedula=?', (cedula,))
        row = c.fetchone()
        if row:
            nombre, mesa = row
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute('INSERT INTO entries VALUES (?,?,?,?)',
                      (ts, st.session_state.username, cedula, extra))
            conn.commit()
            st.session_state.qr_result = ('accepted', (nombre, mesa))
        else:
            st.session_state.qr_result = ('rejected', None)
    st.session_state.qr_input = ''

# ---------- Estado inicial ----------
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ''
if 'qr_result' not in st.session_state:
    st.session_state.qr_result = None

# ---------- Login / Registro ----------
if not st.session_state.logged_in:
    st.title('Control de Acceso - Evento SPH')
    choice = st.sidebar.selectbox('Menú', ['Login', 'Registrar'])
    if choice == 'Registrar':
        new_user = st.text_input('Usuario', key='new_user')
        new_pass = st.text_input('Contraseña', type='password', key='new_pass')
        if st.button('Registrar'):
            if register_user(new_user, new_pass):
                st.success('Usuario creado. Inicie sesión.')
            else:
                st.error('El usuario ya existe.')
    else:
        user = st.text_input('Usuario', key='login_user')
        pwd = st.text_input('Contraseña', type='password', key='login_pass')
        if st.button('Ingresar'):
            if login_user(user, pwd):
                st.session_state.logged_in = True
                st.session_state.username = user
                st.success(f'Bienvenido, {user}!')
            else:
                st.error('Usuario o contraseña incorrectos')
    st.stop()

# ---------- Navegación principal ----------
st.sidebar.write(f'Usuario: **{st.session_state.username}**')
page = st.sidebar.radio('Navegación', ['Admin', 'Escaneo QR', 'Consulta Cedula', 'Exportar Datos'])

# ---------- Página Admin ----------
if page == 'Admin':
    st.header('Administración')
    if st.session_state.username != 'admin':
        st.error('Solo administrador puede acceder')
    else:
        st.info('Admin: usuario `admin`, contraseña `admin`')
        if st.button('Reiniciar Evento (borrar registros y asistentes)'):
            c.execute('DELETE FROM entries')
            c.execute('DELETE FROM event_data')
            conn.commit()
            st.success('Datos borrados: registros de ingreso y asistentes eliminados.')
        st.subheader('Importar Usuarios')
        up_users = st.file_uploader('Excel (.xlsx) con columnas Usuario y Password', type='xlsx', key='up1')
        if up_users:
            dfu = pd.read_excel(up_users)
            dfu.columns = dfu.columns.str.strip()
            added = sum(register_user(str(r['Usuario']), str(r['Password'])) for _, r in dfu.iterrows())
            st.success(f'{added} usuarios importados.')
        st.subheader('Importar Datos del Evento')
        up_ev = st.file_uploader('Excel (.xlsx) con columnas Cedula, Nombre y Mesa', type='xlsx', key='up2')
        if up_ev:
            dfe = pd.read_excel(up_ev)
            dfe.columns = dfe.columns.str.strip()
            dfe['Cedula'] = dfe['Cedula'].astype(str)
            c.execute('DELETE FROM event_data')
            for _, r in dfe.iterrows():
                c.execute('INSERT INTO event_data VALUES (?,?,?)',
                          (r['Cedula'], r['Nombre'], str(r['Mesa'])))
            conn.commit()
            st.success('Datos de evento importados y guardados.')

# ---------- Página Escaneo QR ----------
elif page == 'Escaneo QR':
    st.header('Escaneo QR')
    count_data = c.execute('SELECT COUNT(*) FROM event_data').fetchone()[0]
    if count_data == 0:
        st.warning('No hay datos de evento. Importa primero en Admin.')
    else:
        count = c.execute('SELECT COUNT(*) FROM entries').fetchone()[0]
        st.subheader(f'Total ingresados: {count}')
        st.text_input('Escanee el QR', key='qr_input', on_change=process_qr)
        if st.session_state.qr_result:
            status, info = st.session_state.qr_result
            if status == 'accepted':
                nombre, mesa = info
                st.markdown("<h1 style='color:green;'>INGRESO ACEPTADO</h1>", unsafe_allow_html=True)
                st.markdown(f"<h2 style='color:green;'>Nombre: {nombre}</h2>", unsafe_allow_html=True)
                st.success(f'SU NÚMERO DE MESA ES: {mesa}')
            elif status == 'duplicate':
                ts_prev = info
                st.markdown("<h1 style='color:red;'>PERSONA YA INGRESÓ</h1>", unsafe_allow_html=True)
                st.error(f'FECHA Y HORA DE INGRESO: {ts_prev}')
            else:
                st.markdown("<h1 style='color:red;'>INGRESO RECHAZADO</h1>", unsafe_allow_html=True)
            st.session_state.qr_result = None

# ---------- Página Consulta Cedula ----------
elif page == 'Consulta Cedula':
    st.header('Consulta por Cédula')
    count_data = c.execute('SELECT COUNT(*) FROM event_data').fetchone()[0]
    if count_data == 0:
        st.warning('No hay datos de evento. Importa primero en Admin.')
    else:
        cid = st.text_input('Número de cédula', key='cid_query')
        if st.button('Consultar'):
            c.execute('SELECT mesa FROM event_data WHERE cedula=?', (cid,))
            row = c.fetchone()
            if row:
                st.success(f'SU NÚMERO DE MESA ES: {row[0]}')
            else:
                st.error('Cédula no encontrada')

# ---------- Página Exportar Datos ----------
elif page == 'Exportar Datos':
    st.header('Exportar registros')
    df_e = pd.read_sql('SELECT * FROM entries', conn)
    buf = io.BytesIO()
    df_e.to_excel(buf, index=False, engine='openpyxl')
    buf.seek(0)
    st.download_button('Descargar Excel', buf,
                       'ingresos_evento.xlsx',
                       'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
