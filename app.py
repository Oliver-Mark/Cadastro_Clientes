import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import psycopg2
from psycopg2.errors import UniqueViolation
import bcrypt
import jwt
import datetime

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CHAVE_SECRETA = os.environ.get("CHAVE_SECRETA")

CONFIGURACAO_DB = {
    "dbname": "clientes_db",
    "user": "postgres",
    "password": os.environ.get("DB_SENHA"),
    "host": "localhost",
    "port": os.environ.get("PORTA")
}

def get_db_connection():
    return psycopg2.connect(**CONFIGURACAO_DB)

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                    id SERIAL PRIMARY KEY,
                    nome VARCHAR(100) NOT NULL, 
                    email VARCHAR(100) UNIQUE NOT NULL, 
                    senha VARCHAR(255) NOT NULL
                 )''')
    conn.commit()
    conn.close()

init_db()

class UsuarioCadastro(BaseModel):
    nome: str
    email: EmailStr 
    senha: str

class UsuarioLogin(BaseModel):
    email: EmailStr
    senha: str

@app.post("/cadastro")
def cadastrar(user: UsuarioCadastro):
    senha_hash = bcrypt.hashpw(user.senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO usuarios (nome, email, senha) VALUES (%s, %s, %s)", 
                  (user.nome, user.email, senha_hash))
        conn.commit()
        return {"mensagem": "Usuário cadastrado com sucesso!"}
    except UniqueViolation:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=400, detail="E-mail já cadastrado.")
    finally:
        if conn:
            conn.close()

@app.post("/login")
def login(user: UsuarioLogin):
    conn = None
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, nome, senha FROM usuarios WHERE email = %s", (user.email,))
        resultado = c.fetchone()
    finally:
        if conn:
            conn.close()

    if not resultado:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    user_id, nome, senha_db = resultado
    
    if not bcrypt.checkpw(user.senha.encode('utf-8'), senha_db.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    payload = {
        "id": user_id,
        "nome": nome,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, CHAVE_SECRETA, algorithm="HS256")
    return {"access_token": token}

def verificar_token(authorization: str = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token não fornecido")
    
    token = authorization.split(" ")[1] 
    try:
        payload = jwt.decode(token, CHAVE_SECRETA, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado. Faça login novamente.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido.")

@app.get("/area-protegida")
def area_protegida(usuario = Depends(verificar_token)):
    return {"mensagem": f"Acesso liberado! Bem-vindo à área protegida, {usuario['nome']}."}