from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import datetime
from datetime import UTC
import json
import re
from pathlib import Path
import socket
from pydantic import BaseModel
from typing import Optional
from config import (
    SECRET_KEY, 
    ARQUIVO_JSON, 
    REGISTRO_JSON,
    BASE_DIR
)

app = FastAPI()

# ================== MODELOS ==================
class CadastroModel(BaseModel):
    cpf: str
    nome: str
    email: str
    celular: str
    data_cadastro: Optional[str] = None

class CPFRequest(BaseModel):
    cpf: str

class AtividadeRequest(BaseModel):
    atividade: str
    cpf: str

class QRCodeModel(BaseModel):
    qr_data: str


# ================== FUNÇÕES AUXILIARES ==================
def carregar_registros():
    if REGISTRO_JSON.exists():
        with open(REGISTRO_JSON, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def salvar_registro(registro_data: dict):
    registros = carregar_registros()
    registros.append(registro_data)
    with open(REGISTRO_JSON, "w", encoding="utf-8") as f:
        json.dump(registros, f, ensure_ascii=False, indent=4)

def carregar_dados(arquivo):
    if arquivo.exists():
        with open(arquivo, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def salvar_dados(dados: list, arquivo):
    with open(arquivo, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)

def decrypt_cpf(encrypted_base64: str) -> str:
    raw = base64.b64decode(encrypted_base64)
    if len(raw) < 17:
        raise ValueError("Base64 inválido ou muito curto")

    iv = raw[:16]
    ct_b64_ascii = raw[16:]
    ciphertext = base64.b64decode(ct_b64_ascii)

    key_hex = sha256(SECRET_KEY.encode('utf-8')).hexdigest()
    key = key_hex[:32].encode('ascii')

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    return data.decode('utf-8')

def encrypt_cpf(cpf: str) -> str:
    iv = os.urandom(16)
    key_hex = sha256(SECRET_KEY.encode('utf-8')).hexdigest()
    key = key_hex[:32].encode('ascii')

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(cpf.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    ct_b64 = base64.b64encode(ciphertext).decode('ascii')
    combined = iv + ct_b64.encode('ascii')
    return base64.b64encode(combined).decode('ascii')

def formatar_cpf(cpf: str) -> str:
    return re.sub(r'\D', '', cpf)

def verificar_cpf(cpf: str, arquivo) -> dict:
    cpf_formatado = formatar_cpf(cpf)
    if not re.match(r'^\d{11}$', cpf_formatado):
        return {"status": "error", "message": "CPF inválido - deve conter 11 dígitos"}

    dados = carregar_dados(arquivo)
    for usuario in dados:
        if usuario.get('cpf') == cpf_formatado:
            return {"status": "success", "message": "CPF encontrado na base de dados"}
    return {"status": "error", "message": "CPF não encontrado na base de dados"}

def verificar_atividade(cpf: str, atividade, arquivo) -> dict:
    cpf_formatado = formatar_cpf(cpf)
    if not re.match(r'^\d{11}$', cpf_formatado):
        return {"status": "error", "message": "CPF inválido - deve conter 11 dígitos"}
    dados = carregar_dados(arquivo)
    for usuario in dados:
        if usuario.get('cpf') == cpf_formatado and usuario.get('atividade') == atividade:
            return {"status": "success", "usuario": usuario}
    return {"status": "error", "message": "Atividade não encontrada para este CPF"}

def registrar_atividade(cpf: str, atividade: str) -> dict:
    cpf_formatado = formatar_cpf(cpf)
    if not re.match(r'^\d{11}$', cpf_formatado):
        return {"status": "error", "message": "CPF inválido - deve conter 11 dígitos"}
    if not atividade.strip():
        return {"status": "error", "message": "Atividade não pode estar vazia"}

    resultado_verificacao = verificar_cpf(cpf_formatado, ARQUIVO_JSON)
    if resultado_verificacao["status"] == "success":
        resultado_atividade = verificar_atividade(cpf_formatado, atividade.strip(), REGISTRO_JSON)
        if resultado_atividade["status"] == "error":
            novo_registro = {
                "cpf": cpf_formatado,
                "atividade": atividade.strip(),
                "data_hora": datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
            }
            salvar_registro(novo_registro)
            return {"status": "success", "message": "Atividade registrada com sucesso"}
        return {"status": "error", "message": "Atividade já registrada"}
    return {"status": "error", "message": "CPF não consta na base de dados"}


# ================== ROTAS API PURA ==================
@app.post("/cadastrar")
async def cadastrar(usuario: CadastroModel):
    if not re.match(r'^\d{11}$', usuario.cpf):
        return JSONResponse(status_code=400, content={"error": "CPF inválido"})

    dados = carregar_dados(ARQUIVO_JSON)
    if any(u['cpf'] == usuario.cpf for u in dados):
        return JSONResponse(status_code=400, content={"error": "CPF já cadastrado"})

    if usuario.data_cadastro is None:
        usuario.data_cadastro = datetime.datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

    dados.append(usuario.dict())
    salvar_dados(dados, ARQUIVO_JSON)
    return {"status": "success", "message": "Cadastro realizado com sucesso"}

@app.post("/verificar-cpf")
async def verificar_cpf_endpoint(cpf_request: CPFRequest):
    return verificar_cpf(cpf_request.cpf, ARQUIVO_JSON)

@app.post("/registrar_atividade")
async def registrar_atividade_endpoint(atividade_request: AtividadeRequest):
    return registrar_atividade(atividade_request.cpf, atividade_request.atividade)

@app.post("/process-qrcode")
async def process_qrcode(qr_data: QRCodeModel):
    try:
        cpf = decrypt_cpf(qr_data.qr_data)
        if not re.match(r'^\d{11}$', cpf):
            return {"status": "error", "message": "CPF inválido no QR Code"}
        atividade = "skyline"
        return registrar_atividade(cpf, atividade)
    except Exception as e:
        return {"status": "error", "message": f"Falha ao processar QRCode: {str(e)}"}


# ================== MAIN ==================
if __name__ == "__main__":
    import uvicorn
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"\nAPI disponível em:")
    print(f"http://localhost:8000")
    print(f"http://{local_ip}:8000\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
