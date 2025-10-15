# function_app.py
import os
import httpx
import base64
import fitz
import logging
import json
import asyncio
import uuid
import csv # <--- NUEVO: Importado para generar el reporte
import io  # <--- NUEVO: Importado para manejar archivos en memoria
import re  # <--- NUEVO: Importado para procesar el texto del análisis
from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
from io import BytesIO
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)

# --- CONFIGURACIÓN Y CONSTANTES ---
AZURE_API_KEY = os.getenv("AZURE_OPENAI_KEY")
AZURE_ENDPOINT = "https://pid-analisis-ai.openai.azure.com/"
DEPLOYMENT_NAME = "Analisis_de_riesgos_PID"
API_VERSION = "2024-05-01-preview"
SAFE_PAYLOAD_LIMIT_MB = 18.0

# --- GLOSARIO Y PROMPT ---
GLOSARIO_DE_TERMINOS = {
    "CSO": "CAR SEAL OPEN", "CSC": "CAR SEAL CLOSE", "NO": "NORMALLY OPENED",
    "NC": "NORMALLY CLOSED", "AG": "ABOVE GROUND", "UG": "UNDER GROUND",
    "ASC": "ANALIZER CONTROL SYSTEM", "S/S": "START/STOP", "CCP": "COMPRESSOR CONTROL PANEL",
    "DCS": "DISTRIBUTED CONTROL SYSTEM", "D/P": "DIFFERENTIAL PRESSURE", "ESD": "EMERGENCY SHUTDOWN",
    "LSC": "LOAD SHARING CONTROLLER", "PLC": "PROGRAMMABLE LOGIC CONTROLLER", "PSD": "PROCESS SHUTDOWN",
    "SCADA": "SUPERVISORY CONTROL AND DATA ACQUISITION", "MDC": "MOTOR CONTROL CENTER",
    "MOV": "MOTOR ACTUATED VALVE", "USO": "UNIT SHUTDOWN", "BMS": "BURNER MANAGEMENT SYSTEM",
    "SOV": "SHUTDOWN VALVE", "CCS": "COMPUTER CONTROL SYSTEM", "CEMS": "CONTINUOUS EMISSION MONITORING SYSTEM",
    "MMS": "MACHINE MONITORING SYSTEM", "SIS": "SAFETY INSTRUMENT SYSTEM", "VMS": "VIBRATION MONITORING SYSTEM",
    "ZSC": "VALVE CLOSED LIMIT SWITCH", "ZSO": "VALVE OPEN LIMIT SWITCH", "BOV": "BLOWDOWN VALVE",
    "DHSV": "SUB-SURFACE SAFETY VALVE", "XOXV": "EMERGENCY SHUTDOWN VALVE"
}
glosario_formateado = "\n".join([f"- **{termino}:** {definicion}" for termino, definicion in GLOSARIO_DE_TERMINOS.items()])
PROMPT_ANALISTA_RIESGOS = f"""
Actúa como un ingeniero de procesos senior, experto en seguridad funcional (HAZOP, LOPA), con un temperamento extremadamente meticuloso y paranoico. Tu reputación depende de encontrar TODOS los riesgos posibles.

**METODOLOGÍA DE ANÁLISIS OBLIGATORIA (PENSAMIENTO PASO A PASO):**
Antes de generar tu respuesta JSON final, sigue estos pasos mentalmente para cada cambio identificado:
1.  **Contextualizar:** Lee primero los documentos de alcance/filosofía para entender la razón del cambio.
2.  **Identificar:** Localiza cada marca de revisión. Tu análisis debe cubrir dos tipos de marcas:
    * **Nubes/Triángulos ROJOS:** Indican adiciones o modificaciones.
    * **Áreas con Sombreado GRIS (hatching):** Indican la demolición o eliminación de equipos.
3.  **Describir:** Describe textualmente el cambio técnico específico. Incluye siempre el **TAG** del equipo principal afectado (ej: "Se añade la válvula de control TV-101", "Se elimina la bomba P-505B").
4.  **Evaluar (Análisis de Modos de Falla):**
    * **Para adiciones/modificaciones (nubes rojas):** Evalúa los modos de falla del nuevo equipo. Ejemplos: ¿Qué pasa si la nueva válvula falla cerrada/abierta? ¿Qué pasa si la nueva bomba se detiene o funciona en seco? ¿Qué pasa si el nuevo transmisor da una lectura falsa (alta/baja)?
    * **Para eliminaciones (sombreado gris):** Evalúa las consecuencias de la ausencia del equipo. Ejemplos: ¿Se pierde redundancia? ¿Se elimina una barrera de seguridad? ¿Se pierde la capacidad de aislar una sección para mantenimiento?
5.  **Formular:** Solo después de la evaluación, formula el riesgo, causa, ubicación y recomendación en el formato JSON.

**BASE DE CONOCIMIENTO:**
Te proporcionaré una base de conocimiento con leyendas de símbolos y un glosario. Úsalos como referencia principal.
**Glosario de Términos:**
{glosario_formateado}

**REGLAS CRÍTICAS:**
1.  **ENFOQUE COMPLETO:** Tu análisis debe centrarse en los cambios dentro de las **marcas ROJAS** y las áreas con **sombreado GRIS**.
2.  **CASO SIN MARCAS:** Si en los planos del usuario no hay NINGUNA de estas marcas, tu única respuesta debe ser el objeto JSON: `{{"error": "No se encontraron marcas de revisión (rojas o grises) para analizar."}}`
3.  **NO TE LIMITES:** Tu análisis debe ser EXHAUSTIVO. Si encuentras 10 riesgos, debes reportar los 10.

**FORMATO DE RESPUESTA OBLIGATORIO:**
A menos que aplique la regla #2, tu respuesta DEBE ser exclusivamente un objeto JSON válido.
{{
  "riesgos_identificados": [
    {{
      "id": "integer",
      "riesgo_titulo": "string",
      "descripcion": "string (Debe incluir el TAG del equipo principal)",
      "ubicacion": "_**string (DEBE incluir el TAG del equipo, ej: 'P-750A', y el nombre del plano extraido de los campos LOC y DWG, ej:'PF2-101')**_",
      "causa_potencial": "string (Debe considerar los modos de falla específicos)",
      "recomendacion": "string (Debes proponer una 'Recomendación Principal' que sea la solución de ingeniería más segura. Seguido de esto, si es viable, añade una o varias 'Alternativa Práctica' enfocadas en operaciones o mantenimiento."
    }}
  ]
}}
"""

app = FastAPI()
# --- CORS ---
origins = ["*"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- CACHE DE SESIÓN Y BASE DE CONOCIMIENTO ---
SESSION_CACHE = {}
KNOWLEDGE_BASE_URLS = []
KNOWLEDGE_BASE_SIZE_BYTES = 0

def get_base64_size_bytes(data_url: str) -> int:
    base64_string = data_url.split(",")[1]
    return (len(base64_string) * 3) / 4

@app.on_event("startup")
async def load_knowledge_base():
    global KNOWLEDGE_BASE_SIZE_BYTES
    logging.info("Iniciando carga de la base de conocimiento (archivos de imagen)...")
    kb_folder = "knowledge_base"
    if not os.path.isdir(kb_folder):
        logging.warning(f"La carpeta de la base de conocimiento '{kb_folder}' no existe.")
        return
    for filename in os.listdir(kb_folder):
        if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            try:
                filepath = os.path.join(kb_folder, filename)
                with open(filepath, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                    mime_type = "image/jpeg" if filename.lower().endswith(('.jpg', '.jpeg')) else "image/png"
                    data_url = f"data:{mime_type};base64,{encoded_string}"
                    KNOWLEDGE_BASE_URLS.append(data_url)
                    KNOWLEDGE_BASE_SIZE_BYTES += get_base64_size_bytes(data_url)
                logging.info(f"Procesado archivo de conocimiento: {filename}")
            except Exception as e:
                logging.error(f"Error al cargar el archivo de conocimiento {filename}: {e}")
    if KNOWLEDGE_BASE_URLS:
        logging.info(f"Base de conocimiento cargada con {len(KNOWLEDGE_BASE_URLS)} imágenes. Tamaño total: {KNOWLEDGE_BASE_SIZE_BYTES / 1024 / 1024:.2f} MB")
    else:
        logging.warning("La base de conocimiento está vacía o no contiene imágenes.")

async def process_file_to_data_urls(file: UploadFile) -> List[str]:
    content = await file.read()
    if file.content_type == "application/pdf":
        try:
            pdf_document = fitz.open(stream=BytesIO(content), filetype="pdf")
            return [f"data:image/png;base64,{base64.b64encode(page.get_pixmap(dpi=300).tobytes('png')).decode('utf-8')}" for page in pdf_document]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error al procesar el PDF del usuario '{file.filename}': {e}")
    else:
        raise HTTPException(status_code=400, detail=f"Tipo de archivo no soportado: '{file.content_type}'. Solo se aceptan archivos PDF.")

async def send_analysis_request(client, payload):
    full_endpoint = f"{AZURE_ENDPOINT}openai/deployments/{DEPLOYMENT_NAME}/chat/completions?api-version={API_VERSION}"
    headers = {"Content-Type": "application/json", "api-key": AZURE_API_KEY}
    response = await client.post(full_endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()

@app.post("/analyze")
async def analyze_documents(scope_files: List[UploadFile] = File(None), planos: List[UploadFile] = File(...)):
    session_id = str(uuid.uuid4())
    logging.info(f"Iniciando nueva sesión de análisis: {session_id}")

    all_user_files = (scope_files or []) + (planos or [])
    processed_user_images = []
    for file in all_user_files:
        urls = await process_file_to_data_urls(file)
        processed_user_images.extend(urls)
    
    # MODIFICADO: Se guarda un diccionario en la caché, no solo las imágenes
    SESSION_CACHE[session_id] = {
        "images": processed_user_images,
        "analysis": None # El análisis se guardará después de ser generado
    }
    logging.info(f"Sesión {session_id}: {len(processed_user_images)} imágenes de usuario guardadas en cache.")

    batches = []
    current_batch_size = KNOWLEDGE_BASE_SIZE_BYTES
    current_batch_images = []
    SAFE_LIMIT_BYTES = SAFE_PAYLOAD_LIMIT_MB * 1024 * 1024
    for image_url in processed_user_images:
        image_size = get_base64_size_bytes(image_url)
        if image_size + KNOWLEDGE_BASE_SIZE_BYTES > SAFE_LIMIT_BYTES:
            raise HTTPException(status_code=400, detail=f"Una de las páginas procesadas es demasiado grande ({image_size/1024/1024:.2f}MB) para ser enviada.")
        if current_batch_size + image_size > SAFE_LIMIT_BYTES and current_batch_images:
            batches.append(current_batch_images)
            current_batch_images = []
            current_batch_size = KNOWLEDGE_BASE_SIZE_BYTES
        current_batch_images.append(image_url)
        current_batch_size += image_size
    if current_batch_images:
        batches.append(current_batch_images)
    if not batches and not processed_user_images:
        raise HTTPException(status_code=400, detail="No se proporcionaron archivos de planos para analizar.")

    logging.info(f"Análisis inicial: se ha dividido la solicitud en {len(batches)} lote(s).")
    
    final_risks = []
    risk_id_counter = 1
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            tasks = []
            for i, image_batch in enumerate(batches):
                user_content = [{"type": "text", "text": "Analiza los siguientes documentos y devuelve tu análisis exclusivamente en formato JSON."}]
                if KNOWLEDGE_BASE_URLS:
                    user_content.append({"type": "text", "text": "--- INICIO: BASE DE CONOCIMIENTO ---"})
                    user_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in KNOWLEDGE_BASE_URLS])
                    user_content.append({"type": "text", "text": "--- FIN: BASE DE CONOCIMIENTO ---"})
                user_content.append({"type": "text", "text": f"--- INICIO: DOCUMENTOS DEL LOTE {i+1}/{len(batches)} ---"})
                user_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in image_batch])
                payload = {"messages": [{"role": "system", "content": PROMPT_ANALISTA_RIESGOS}, {"role": "user", "content": user_content}], "max_tokens": 4096, "temperature": 0.1, "top_p": 0.8, "response_format": {"type": "json_object"}}
                tasks.append(send_analysis_request(client, payload))
            
            results = await asyncio.gather(*tasks)

            for result in results:
                analysis_content_str = result.get("choices", [{}])[0].get("message", {}).get("content")
                if analysis_content_str:
                    analysis_json = json.loads(analysis_content_str)
                    if "riesgos_identificados" in analysis_json:
                        for risk in analysis_json["riesgos_identificados"]:
                            risk["id"] = risk_id_counter
                            final_risks.append(risk)
                            risk_id_counter += 1
                    elif "error" in analysis_json:
                        logging.warning(f"Un lote devolvió una nota: {analysis_json['error']}")
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error de la API de Azure: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

    final_response = {"riesgos_identificados": final_risks}
    # MODIFICADO: Guardamos el análisis final en la caché de la sesión
    SESSION_CACHE[session_id]["analysis"] = final_response
    
    return {"raw_analysis": json.dumps(final_response), "session_id": session_id}


class ChatMessage(BaseModel):
    role: str
    content: Any

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    session_id: str

@app.post("/chat")
async def handle_chat(chat_request: ChatRequest):
    if not AZURE_API_KEY:
        raise HTTPException(status_code=500, detail="La clave de API de Azure no está configurada.")

    session_id = chat_request.session_id
    # MODIFICADO: Se obtiene el diccionario completo de la sesión
    session_data = SESSION_CACHE.get(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Sesión no encontrada o expirada. Por favor, inicie un nuevo análisis.")
    
    cached_images = session_data.get("images", [])

    chat_history_from_client = [msg.dict() for msg in chat_request.messages]
    user_multimodal_content = []
    
    last_user_question = chat_history_from_client[-1]['content']
    user_multimodal_content.append({"type": "text", "text": last_user_question})
    
    if KNOWLEDGE_BASE_URLS:
        user_multimodal_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in KNOWLEDGE_BASE_URLS])
    user_multimodal_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in cached_images])
    
    messages_for_api = []
    messages_for_api.append({"role": "system", "content": PROMPT_ANALISTA_RIESGOS})
    messages_for_api.extend(chat_history_from_client[:-1])
    messages_for_api.append({"role": "user", "content": user_multimodal_content})
    
    payload = { "messages": messages_for_api, "max_tokens": 2048, "temperature": 0.5, "top_p": 0.9 }
    
    headers = {"Content-Type": "application/json", "api-key": AZURE_API_KEY}
    full_endpoint = f"{AZURE_ENDPOINT}openai/deployments/{DEPLOYMENT_NAME}/chat/completions?api-version={API_VERSION}"

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            response = await client.post(full_endpoint, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            ai_response = data.get("choices", [{}])[0].get("message", {}).get("content")
            if not ai_response:
                raise HTTPException(status_code=500, detail="Respuesta vacía de la API de Azure.")
            
            return {"response": ai_response}
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error de la API de Azure: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

# --- INICIO: NUEVO ENDPOINT DE DESCARGA ---

class DownloadRequest(BaseModel):
    session_id: str

@app.post("/download_report")
async def download_report(request: DownloadRequest):
    session_id = request.session_id
    session_data = SESSION_CACHE.get(session_id)

    if not session_data:
        raise HTTPException(status_code=404, detail="Sesión no válida o no encontrada.")
    
    analysis_data = session_data.get("analysis")
    if not analysis_data or "riesgos_identificados" not in analysis_data:
        raise HTTPException(status_code=400, detail="No se encontró un análisis de riesgos en esta sesión para descargar.")
    
    riesgos = analysis_data["riesgos_identificados"]
    
    # Generar el archivo CSV en memoria con el formato "What If"
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_ALL)
    
    # Escribir la fila de encabezados
    writer.writerow(['What If', 'Consecuencia', 'Mitigación'])
    
    # Escribir los datos de cada riesgo
    for riesgo in riesgos:
        what_if_text = f"{riesgo.get('descripcion', 'N/A')} (Ubicación: {riesgo.get('ubicacion', 'N/A')})".replace('\n', ' ')
        consecuencia_text = riesgo.get('causa_potencial', 'N/A').replace('\n', ' ')
        mitigacion_text = riesgo.get('recomendacion', 'N/A').replace('\n', ' ')
        
        writer.writerow([what_if_text, consecuencia_text, mitigacion_text])
        
    # Devolver el archivo CSV en la respuesta HTTP
    csv_data = output.getvalue().encode('utf-8-sig') 
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=analisis_de_riesgos_what-if.csv"}
    )
# --- FIN: NUEVO ENDPOINT DE DESCARGA ---

@app.get("/")
def read_root():
    return {"message": "API de Análisis de Riesgos está en línea."}