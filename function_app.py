import os
import httpx
import base64
import fitz  # PyMuPDF
import logging
import json
import asyncio
import uuid
import csv 
import io  
import re 
from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
# --- IMPORTACIÓN MODIFICADA ---
from typing import List, Dict, Any, Optional 
from io import BytesIO
from pydantic import BaseModel
# --- NUEVAS IMPORTACIONES PARA AZURE IDENTITY ---
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

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
    "DHSV": "SUB-SURFACE SAFETY VALVE", "XOXV": "EMERGENCY SHUTDOWN VALVE",
    "HH": "Alarma de Muy Alto", "H": "Alarma de Alto", "L": "Alarma de Bajo", "LL": "Alarma de Muy Bajo", "FP": "Paso Completo",
    "CONFIGURED ALARMS": "Alarmas configuradas en el sistema de control de procesos",
    "Spectacle Blind (Normally Open)": "Figura en ocho normally abierta",
    "Spectacle Blind (Normally Closed)": "Figura en ocho normally Cerrada",
    "Connecting Reducer": "Reducción", "Eccentric Reducer": "Reducción excéntrica",
    "Silencer (Vent to Atmosphere)": "Silenciador con venteo a la atmosfera",
    "Screwed Cap": "Tapón roscado", "Weld Cap": "Tapón Soldado", "Thief Hatch": "Tapa de muestreo",
    "Blind Flange": "Ciego", "Ejector/Eductor": "Eyector/Eductor", "Package Unit / Skid": "Unidad paquete/skid",
    "Demister": "Eliminador de neblina", "Packing": "Empaquetado", "Line Number Change": "Cambio de numero de línea",
    "Tie-in": "Empalme en tuberías/Tie-in", "Utility Station": "Estación de utilidades",
    "Integral Interlock": "Enclavamiento integral con sistema de apagado",
    "Radar Tank Gauge": "Medidor de nivel por radar", "Vortex Flowmeter": "Medidor de flujo tipo vortex",
    "Ultrasonic Flowmeter": "Medidor de flujo ultrasónico", "In-line Flowmeter": "Medidor de flujo en línea con transmisor",
    "Positive Displacement Flowmeter": "Medidor de flujo de desplazamiento positivo",
    "Turbine/Propeller Meter": "Medidor de flujo de turbina o hélice",
    "Orifice Plate": "Platina de orificio", "Flow Glass / Sight Glass": "Visor de flujo",
    "Rotameter": "Rotametro o linea de purga", "Flow Switch": "Interruptor de flujo",
    "Magnetic (Flow)": "Magnetico (flujo)", "Ultrasonic (Flow)": "Ultrasonico (flujo)",
    "Averaging Pitot Tube": "Tubo Pitot promediador", "Flow Nozzle": "Boquilla de flujo", "Venturi": "Venturi",
    "Wedge Meter": "Medidor de cuña", "Flume": "Canal abierto", "Orifice in Quick Change Fitting": "Orificio en accesorio de cambio rapido",
    "Target (Flow)": "Objetivo (flujo)", "Bulk Drum": "Tambor de almacenamiento", "Diaphragm Pump": "Bomba de diafragmas",
    "Basket Strainer": "Filtro de canastilla", "Cone Roof Tank": "Tanque de techo cónico",
    "Concrete Pit": "Foso de concreto", "Air Cooler": "Intercambiador con aire",
    "Hairpin/U-Tube Exchanger": "Intercambiador tipo horquilla o tipo U",
    "Gas/Diesel Engine": "Motor a gas o diesel", "Horizontal Vessel": "Vasija horizontal", "Vertical Vessel": "Vasija vertical",
    "Flare": "Tea", "Spring Diaphragm Actuator": "Actuador de resorte con diafragma y posicionador",
    "On/Off Actuator": "Actuador de posición on/off o parada de emergencia",
    "Adjustable Choke (Angle Body)": "Choque ajustable con cuerpo en ángulo",
    "Adjustable Choke (In-line)": "Choque ajustable en línea", "Fixed Bean Choke": "Choque de boquilla fija",
    "Fixed Choke (Angle Body)": "Choque fijo con cuerpo en ángulo", "Block and Bleed Valve": "Válvula de bloqueo y purga",
    "Check Valve": "Válvula choque", "Stop Check Valve": "Válvula choque y cierre",
    "Solenoid Valve (Manual/Electric Reset)": "Válvula solenoide con reinicio local manual o electrico"
}
glosario_formateado = "\n".join([f"- **{key}:** {value}" for key, value in GLOSARIO_DE_TERMINOS.items()])

# --- PROMPT MEJORADO CON TODAS LAS REGLAS DE RETROALIMENTACIÓN ---
PROMPT_ANALISTA_RIESGOS = f"""
Actúa como un ingeniero de procesos senior, experto en seguridad funcional (HAZOP, LOPA), con un temperamento extremadamente meticuloso y paranoico. Tu reputación depende de encontrar TODOS los riesgos posibles.

**METODOLOGÍA DE ANÁLISIS OBLIGATORIA (PENSAMIENTO PASO A PASO):**
1.  **Revisión Inicial de Planos (Regla #1):** Escanea **TODOS** los planos del usuario (ignora el alcance por ahora) buscando **marcas de revisión**. Estas marcas son **nubes rojas (dibujadas con forma de nube) O áreas con sombreado gris (hatching)** que indican un cambio.
2.  **Decisión Crítica (Regla #2):**
    * **SI NO ENCUENTRAS NINGUNA MARCA (ninguna nube roja o sombreado gris):** Detén todo análisis. IGNORA el alcance. Tu ÚNICA respuesta DEBE ser el JSON: `{{"error": "No se encontraron marcas de revisión (nubes rojas o sombreado gris) en los planos para analizar."}}`.
    * **SI ENCUENTRAS MARCAS:** Continúa con el paso 3.
3.  **Contextualizar:** Lee ahora los documentos de alcance/filosofía para entender la **razón** del cambio.
4.  **Identificar y Describir:** Para CADA marca de revisión (roja o gris) en los planos:
    * Describe textualmente el cambio técnico.
    * Identifica el TAG del equipo principal (ej: "P-505B").
    * **Identifica la referencia del plano:** Para este dato, **DEBES USAR** la información de "Fuente de Verdad del Cajetín" que te proporciono en el prompt del usuario.
5.  **Evaluar (Modos de Falla y Mitigaciones):**
    * Para **adiciones (nubes rojas)**: Evalúa los modos de falla del nuevo equipo (ej: ¿válvula falla cerrada/abierta?, ¿transmisor falla alto/bajo?).
    * Para **eliminaciones (sombreado gris)**: Evalúa las consecuencias de la **ausencia** del equipo (ej. pérdida de función, pérdida de redundancia).
    * **Verificar Mitigaciones Existentes:** Antes de recomendar, **inspecciona el P&ID** en busca de mitigaciones ya implementadas (ej. PSVs, instrumentación redundante).
6.  **Formular:** Genera el riesgo, causa y recomendación en formato JSON.

**BASE DE CONOCIMIENTO (USO OBLIGATORIO):**
Tu análisis debe basarse en la siguiente base de conocimiento:
1.  **Imágenes de Leyenda (Símbolos):** Te proporcionaré imágenes de la leyenda de símbolos del proyecto. DEBES usarlas para **identificar visualmente** los equipos.
2.  **Glosario de Términos (Nombres):** El siguiente glosario es la **fuente de verdad única** para la terminología. DEBES usar los términos en español de este glosario para nombrar los equipos que identifiques.

**REGLAS CRÍTICAS:**
1.  **USO ESTRICTO DEL GLOSARIO (REGLA DE FORMATO ESTRICTO):**
    * Tu tarea de identificación es **visual y literal, NO funcional**.
    * **NO DEBES** usar tu conocimiento genérico de ingeniero para nombrar equipos por su función (ej. "bombas dosificadoras").
    * **DEBES** identificar el símbolo en la leyenda y usar el nombre exacto del `GLOSARIO_DE_TERMINOS`.
    * **Ejemplo de Formato INCORRECTO:** "Se añade automatización a las bombas dosificadoras P-750A (Bomba de diafragma)."
    * **Ejemplo de Formato CORRECTO:** "Se añade automatización a la 'Bomba de diafragmas' (TAG: P-750A)."
2.  **PRIORIDAD DEL P&ID:** El P&ID es la fuente única de verdad. Si un documento de alcance contradice lo que se ve en el P&ID, la información visual del **P&ID siempre tiene prioridad**.
3.  **MANEJO DE SOMBREADO GRIS (HATCHING):** Las áreas con sombreado gris indican **"equipos a desmantelar"**. Tu análisis debe centrarse en las **consecuencias de esta eliminación (pérdida de función, redundancia, etc.)**. No reportes eliminaciones si no ves este sombreado.
4.  **MANEJO DE PLANOS SIN MARCAS:** Si (como se describe en la Metodología, Paso 1) no encuentras **NINGUNA** marca de revisión (ni nubes rojas, ni sombreado gris) en **NINGUNO** de los planos del usuario, **DEBES IGNORAR TODOS LOS DEMÁS DOCUMENTOS** y tu única respuesta debe ser el objeto JSON: `{{"error": "No se encontraron marcas de revisión (nubes rojas o sombreado gris) en los planos para analizar."}}`.
5.  **NO TE LIMITES:** Tu análisis debe ser EXHAUSIVO.

**FORMATO DE RESPUESTA OBLIGATORIO (CON MITIGACIONES):**
A menos que aplique la regla #4, tu respuesta DEBE ser exclusivamente un objeto JSON válido.
{{
  "riesgos_identificados": [
    {{
      "id": "integer",
      "riesgo_titulo": "string (Debe ser específico. Combina el tipo de riesgo y el TAG principal. Ej: 'Falla en Bomba de diafragmas (P-750A)')",
      "descripcion": "string (Debe comenzar con el nombre del equipo del Glosario y su TAG. Ej: 'Se añade una Bomba de diafragmas (P-750A)...')",
      "ubicacion": "string (DEBE incluir la referencia del plano usando la 'Fuente de Verdad del Cajetín' que te proporcioné. Ej: 'DWG No: 100-95, REV: 51')",
      "causa_potencial": "string (Debe considerar los modos de falla específicos)",
      "recomendacion": "string (Proponer la 'Recomendación Principal:' y una 'Alternativa Práctica:'. Debe agregar un subtítulo 'Mitigaciones Existentes:' si se encontraron (ej. 'PSV-101 instalada') Si no hay mitigaciones, omitir este subtítulo.)"
    }}
  ]
}}
Si encuentras marcas de revisión, pero después de tu análisis concluyes que NO introducen riesgos, devuelve un array 'riesgos_identificados' vacío.
"""

# --- PROMPT PARA EXTRACCIÓN DE CAJETÍN (ETAPA 1) ---
PROMPT_EXTRACCION_CAJETIN = """
Tu única tarea es actuar como un extractor OCR de alta precisión.
Te daré una o más imágenes, cada una es un 'cajetín' (bloque de título) recortado de un plano.
Analiza cada imagen y extrae el número de plano y la revisión.

Campos a buscar:
1.  **dwg_no**: Busca etiquetas como 'DWG No', 'PLANO No.', 'DRAWING No.', 'DOCUMENT No.', 'DWG N°'.
2.  **rev**: Busca etiquetas como 'REV.', 'REV', 'REVISION'.

Responde OBLIGATORIAMENTE en el siguiente formato JSON. Proporciona "No encontrado" si no puedes leer un valor. No inventes datos.
{
  "extracciones": [
    {
      "pagina": 1,
      "dwg_no": "valor_extraido_1",
      "rev": "valor_extraido_1"
    },
    {
      "pagina": 2,
      "dwg_no": "valor_extraido_2",
      "rev": "valor_extraido_2"
    }
    // ... (una entrada por cada imagen/página que recibas)
  ]
}
"""

# --- PROMPT PARA ANÁLISIS DE SÓLO ALCANCE ---
PROMPT_ANALISTA_ALCANCE = """
Actúa como un ingeniero de procesos senior y experto en seguridad funcional.
Tu tarea es analizar los siguientes documentos de alcance (scope) de un proyecto de ingeniería.
Los documentos se proporcionan como imágenes (páginas de PDF).

**METODOLOGÍA DE ANÁLISIS OBLIGATORIA:**
1.  **Lectura Exhaustiva:** Lee CADA página de los documentos de alcance proporcionados.
2.  **Identificación de Riesgos:** Tu objetivo es encontrar riesgos textuales, no visuales. Busca:
    * **Ambigüedades:** Frases que puedan interpretarse de múltiples maneras (ej. "El sistema debe ser seguro").
    * **Información Faltante:** Puntos críticos que no se definen (ej. "Se instalará una bomba" pero no se especifica el tipo, presión, o control).
    * **Riesgos de Contrato/Operación:** Requisitos que parezcan peligrosos, poco prácticos o que entren en conflicto entre sí.
3.  **Formular:** Genera el riesgo, causa y recomendación en formato JSON.

**FORMATO DE RESPUESTA OBLIGATORIO:**
Tu respuesta DEBE ser exclusivamente un objeto JSON válido.
{{
  "riesgos_identificados": [
    {{
      "id": "integer",
      "riesgo_titulo": "string (Ej: 'Ambigüedad en el sistema de apagado')",
      "descripcion": "string (Describe el riesgo o ambigüedad encontrada en el texto)",
      "ubicacion": "string (Indica 'Documento de Alcance')",
      "causa_potencial": "string (Ej: 'Texto poco claro en la especificación')",
      "recomendacion": "string (Ej: 'Solicitar clarificación al equipo de ingeniería sobre los criterios exactos del sistema de apagado.')"
    }}
  ]
}}
Si no encuentras riesgos, devuelve un array 'riesgos_identificados' vacío.
"""

# --- PROMPT PARA EL CHAT DE SEGUIMIENTO ---
PROMPT_CHAT_RIESGOS = f"""
Actúa como un ingeniero de procesos senior.
Tu tarea es responder preguntas de seguimiento sobre el análisis de riesgos existente.

**REGLAS DE FORMATO:**
1.  **NO USES JSON:** Responde en texto plano/Markdown.
2.  **USA MARKDOWN:** Usa negritas y listas para estructurar la respuesta.

**🚨 REGLAS CRÍTICAS DE SEGURIDAD DE CONTENIDO (AZURE POLICY): 🚨**
El sistema de seguridad de Azure bloqueará tu respuesta si describes daños a personas. Para evitar esto, DEBES seguir estas reglas:

1.  **PROHIBICIÓN ABSOLUTA DE DAÑO HUMANO:**
    * **NUNCA** menciones palabras como: muerte, morir, fallecer, matar, suicidio, herida, lesión, fatalidad, desmembramiento, daño físico, sangre, cuerpo humano.
    * **NUNCA** describas escenarios donde una persona sufra daño.

2.  **ENFOQUE EXCLUSIVO EN ACTIVOS Y PROCESOS:**
    * Describe TODAS las consecuencias negativas **ÚNICAMENTE** en términos de:
        * **Fallas Mecánicas:** (ej. "colapso estructural", "sobrepresión", "rotura de línea", "falla catastrófica del equipo").
        * **Impacto Operativo:** (ej. "parada de planta", "pérdida de producción", "interrupción del servicio").
        * **Integridad de Activos:** (ej. "pérdida de contención", "daño irreversible al activo").
        * **Ambiente:** (ej. "fuga al medio ambiente", "emisiones no controladas").

3.  **EUFEMISMOS TÉCNICOS:**
    * Si el riesgo implica peligro para la vida, usa TÉRMINOS ABSTRACTOS como: "**Incidente de Seguridad de Procesos (PSI)**", "**Evento de Alto Riesgo**", "**Afectación HSE**" o "**Condiciones Inseguras**".

**Ejemplo de Conversión:**
* *MALO (Bloqueado):* "La explosión podría matar a los operadores cercanos."
* *BUENO (Aceptado):* "Una sobrepresión podría causar una falla catastrófica del equipo y un Incidente de Seguridad de Procesos mayor con pérdida de contención."

Responde a la pregunta del usuario aplicando estrictamente estas reglas de censura técnica.
"""

app = FastAPI()
# --- CORS ---
origins = ["*"] 
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- CACHE DE SESIÓN Y BASE DE CONOCIMIENTO ---
SESSION_CACHE = {}

# --- INICIO: CONFIGURACIÓN DE BLOB STORAGE (MODIFICADO) ---
STORAGE_ACCOUNT_URL = os.getenv("STORAGE_ACCOUNT_URL") 
CONTAINER_NAME = "pid-ratings"  
BLOB_NAME = "ratings_log.csv"   

credential = DefaultAzureCredential()
# --- FIN: CONFIGURACIÓN DE BLOB STORAGE ---

KNOWLEDGE_BASE_URLS = []
KNOWLEDGE_BASE_SIZE_BYTES = 0

# --- MODELO DE RATING MODIFICADO ---
class RatingRequest(BaseModel):
    session_id: str
    rating: int
    comment: Optional[str] = None
    tiempo_ahorrado: Optional[str] = None # <--- AÑADIDO

def get_base64_size_bytes(data_url: str) -> int:
    base64_string = data_url.split(",")[1]
    return (len(base64_string) * 3) / 4

@app.on_event("startup")
async def load_knowledge_base():
    # ... (Tu código de load_knowledge_base no cambia) ...
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
    # ... (Tu código de process_file_to_data_urls no cambia) ...
    content = await file.read()
    if file.content_type == "application/pdf":
        try:
            pdf_document = fitz.open(stream=BytesIO(content), filetype="pdf")
            return [f"data:image/png;base64,{base64.b64encode(page.get_pixmap(dpi=300).tobytes('png')).decode('utf-8')}" for page in pdf_document]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error al procesar el PDF del usuario '{file.filename}': {e}")
    else:
        raise HTTPException(status_code=400, detail=f"Tipo de archivo no soportado: '{file.content_type}'. Solo se aceptan archivos PDF.")


async def process_pdf_pages_with_crops(file: UploadFile) -> (List[str], List[str]):
    """
    Procesa un archivo PDF y devuelve dos listas de imágenes base64:
    1. full_pages: Imágenes de la página completa (para análisis de riesgos).
    2. title_blocks: Imágenes recortadas del cajetín (para extracción de DWG/REV).
    """
    content = await file.read()
    if file.content_type != "application/pdf":
        logging.warning(f"Se intentó procesar con recorte un archivo no PDF: {file.filename}")
        return [], []

    full_pages = []
    title_blocks = []
    try:
        pdf_document = fitz.open(stream=BytesIO(content), filetype="pdf")
        for page_num, page in enumerate(pdf_document):
            
            # 1. Obtener la página completa
            try:
                full_pix = page.get_pixmap(dpi=300)
                full_b64 = base64.b64encode(full_pix.tobytes('png')).decode('utf-8')
                full_pages.append(f"data:image/png;base64,{full_b64}")
            except Exception as e:
                logging.error(f"Error al renderizar página completa {page_num} de {file.filename}: {e}")
                full_pages.append("") # Añadir placeholder si falla
            
            # 2. Definir el área de recorte (cajetín)
            rect = page.rect
            
            # --- LÍNEA MODIFICADA (basada en tu feedback) ---
            # Captura el 20% derecho y el 20% inferior de la página.
            crop_box = fitz.Rect(rect.width * 0.80, rect.height * 0.80, rect.width, rect.height)
            
            # 3. Obtener la imagen recortada del cajetín
            try:
                # Aplicamos el crop_box a la página
                page.set_cropbox(crop_box)
                crop_pix = page.get_pixmap(dpi=300) # Renderiza solo el área del crop_box
                crop_b64 = base64.b64encode(crop_pix.tobytes('png')).decode('utf-8')
                title_blocks.append(f"data:image/png;base64,{crop_b64}")
            except Exception as e:
                logging.error(f"Error al renderizar cajetín recortado {page_num} de {file.filename}: {e}")
                title_blocks.append("") # Añadir placeholder si falla
            
            # 4. Restaurar el mediabox para la siguiente iteración (buena práctica)
            page.set_cropbox(page.mediabox)

        return full_pages, title_blocks
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al procesar el PDF '{file.filename}' para recorte: {e}")


async def send_analysis_request(client, payload):
    # ... (Tu código de send_analysis_request no cambia) ...
    full_endpoint = f"{AZURE_ENDPOINT}openai/deployments/{DEPLOYMENT_NAME}/chat/completions?api-version={API_VERSION}"
    headers = {"Content-Type": "application/json", "api-key": AZURE_API_KEY}
    response = await client.post(full_endpoint, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


# --- (MODIFICADO) ENDPOINT /analyze ---
@app.post("/analyze")
async def analyze_documents(scope_files: List[UploadFile] = File(None), planos: List[UploadFile] = File(None)):
    
    session_id = str(uuid.uuid4())
    logging.info(f"Iniciando nueva sesión de análisis: {session_id}")

    if not scope_files and not planos:
        raise HTTPException(status_code=400, detail="Debe proporcionar al menos un archivo (plano o alcance).")

    # --- INICIO: LÓGICA DE PROCESAMIENTO MODIFICADA ---
    processed_scope_images = []
    processed_plano_images = []
    processed_title_blocks = []
    
    if scope_files:
        for file in scope_files:
            try:
                urls = await process_file_to_data_urls(file) # Usa la función original
                processed_scope_images.extend(urls)
            except Exception as e:
                logging.warning(f"Omitiendo archivo de alcance {file.filename} debido a error: {e}")

    # --- LÓGICA DE DECISIÓN: PLANOS vs SÓLO ALCANCE ---
    
    if not planos:
        # --- CASO 1: SÓLO ALCANCE ---
        logging.info(f"Sesión {session_id}: Iniciando análisis de SÓLO ALCANCE.")
        
        SESSION_CACHE[session_id] = {
            "images": processed_scope_images, # Guardar solo imágenes de alcance
            "analysis": None
        }
        
        # (Aquí usamos la lógica de lotes (batching) para las imágenes de alcance)
        batches = create_batches(processed_scope_images, KNOWLEDGE_BASE_URLS)
        if not batches:
             raise HTTPException(status_code=400, detail="No se pudieron procesar los archivos de alcance.")

        logging.info(f"Análisis (Sólo Alcance): se ha dividido la solicitud en {len(batches)} lote(s).")
        
        payloads = []
        for i, image_batch in enumerate(batches):
            user_content = [{"type": "text", "text": "Analiza los siguientes documentos de alcance y devuelve tu análisis exclusivamente en formato JSON."}]
            # (Opcional: puedes incluir la base de conocimiento si es relevante para el alcance)
            # if KNOWLEDGE_BASE_URLS: ...
            user_content.append({"type": "text", "text": f"--- INICIO: DOCUMENTOS DE ALCANCE (LOTE {i+1}/{len(batches)}) ---"})
            user_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in image_batch])
            
            payload = {
                "messages": [
                    {"role": "system", "content": PROMPT_ANALISTA_ALCANCE}, # <-- USAR NUEVO PROMPT
                    {"role": "user", "content": user_content}
                ],
                "max_tokens": 4096, "temperature": 0.1, "top_p": 0.8, 
                "response_format": {"type": "json_object"}
            }
            payloads.append(payload)

    else:
        # --- CASO 2: HAY PLANOS (y posiblemente alcance) ---
        logging.info(f"Sesión {session_id}: Iniciando análisis de PLANOS (con/sin alcance).")
        
        if planos:
            for file in planos:
                try:
                    full_pages, title_blocks = await process_pdf_pages_with_crops(file) 
                    processed_plano_images.extend(full_pages)
                    processed_title_blocks.extend(title_blocks)
                except Exception as e:
                    logging.warning(f"Omitiendo plano {file.filename} debido a error: {e}")

        if not processed_plano_images:
            raise HTTPException(status_code=400, detail="No se proporcionaron archivos de planos válidos para analizar.")

        all_images_for_session = processed_scope_images + processed_plano_images
        SESSION_CACHE[session_id] = {
            "images": all_images_for_session,
            "analysis": None
        }
        logging.info(f"Sesión {session_id}: {len(all_images_for_session)} imágenes totales guardadas en cache.")

        info_extraida_texto = "--- INFORMACIÓN DE CAJETÍN (Fuente de Verdad) ---\nNo se pudo extraer información del cajetín."
        
        # --- ETAPA 1: EXTRACCIÓN DE DATOS DEL CAJETÍN ---
        if processed_title_blocks:
            logging.info(f"Sesión {session_id}: Iniciando Etapa 1 - Extracción de {len(processed_title_blocks)} cajetines.")
            try:
                extraction_content = [{"type": "text", "text": "Extrae el DWG No y REV de las siguientes imágenes de cajetín."}]
                extraction_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in processed_title_blocks if url])
                
                payload_extraccion = {
                    "messages": [
                        {"role": "system", "content": PROMPT_EXTRACCION_CAJETIN},
                        {"role": "user", "content": extraction_content}
                    ],
                    "max_tokens": 1024, "temperature": 0.0,
                    "response_format": {"type": "json_object"}
                }
                async with httpx.AsyncClient(timeout=120.0) as client:
                    extraction_result = await send_analysis_request(client, payload_extraccion)
                    
                content_str = extraction_result.get("choices", [{}])[0].get("message", {}).get("content")
                if content_str:
                    extracted_data = json.loads(content_str).get("extracciones", [])
                    texto_items = []
                    for i, item in enumerate(extracted_data):
                        dwg = item.get('dwg_no', 'No encontrado')
                        rev = item.get('rev', 'No encontrado')
                        texto_items.append(f"Plano (Página {i+1}): DWG No: {dwg}, REV: {rev}")
                    
                    if texto_items:
                        info_extraida_texto = "--- INFORMACIÓN DE CAJETÍN (Fuente de Verdad) ---\n" + "\n".join(texto_items) + "\n--- FIN INFORMACIÓN DE CAJETÍN ---"
                    logging.info(f"Sesión {session_id}: Extracción de cajetín exitosa.")
                
            except Exception as e:
                logging.error(f"Sesión {session_id}: Error en Etapa 1 (Extracción de cajetín): {e}")
        
        # --- ETAPA 2: ANÁLISIS DE RIESGOS ---
        logging.info(f"Sesión {session_id}: Iniciando Etapa 2 - Análisis de Riesgos.")
        
        all_user_images_for_analysis = processed_scope_images + processed_plano_images
        batches = create_batches(all_user_images_for_analysis, KNOWLEDGE_BASE_URLS)
        
        logging.info(f"Análisis (Etapa 2): se ha dividido la solicitud en {len(batches)} lote(s).")
        
        payloads = []
        for i, image_batch in enumerate(batches):
            user_content = [{"type": "text", "text": "Analiza los siguientes documentos y devuelve tu análisis exclusivamente en formato JSON."}]
            if KNOWLEDGE_BASE_URLS:
                user_content.append({"type": "text", "text": "--- INICIO: BASE DE CONOCIMIENTO ---"})
                user_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in KNOWLEDGE_BASE_URLS])
                user_content.append({"type": "text", "text": "--- FIN: BASE DE CONOCIMIENTO ---"})
            
            user_content.append({"type": "text", "text": info_extraida_texto}) # Inyectar datos de Etapa 1

            user_content.append({"type": "text", "text": f"--- INICIO: DOCUMENTOS DEL LOTE {i+1}/{len(batches)} ---"})
            user_content.extend([{"type": "image_url", "image_url": {"url": url}} for url in image_batch])
            
            payload = {
                "messages": [
                    {"role": "system", "content": PROMPT_ANALISTA_RIESGOS}, # <-- USAR PROMPT DE RIESGOS
                    {"role": "user", "content": user_content}
                ],
                "max_tokens": 4096, "temperature": 0.1, "top_p": 0.8,
                "response_format": {"type": "json_object"}
            }
            payloads.append(payload)

    # --- EJECUCIÓN DE LLAMADAS A LA API (Común para ambos casos) ---
    final_risks = []
    risk_id_counter = 1
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            tasks = [send_analysis_request(client, p) for p in payloads]
            results = await asyncio.gather(*tasks)

            for result in results:
                analysis_content_str = result.get("choices", [{}])[0].get("message", {}).get("content")
                if analysis_content_str:
                    try:
                        analysis_json = json.loads(analysis_content_str)
                        if "riesgos_identificados" in analysis_json:
                            for risk in analysis_json["riesgos_identificados"]:
                                risk["id"] = risk_id_counter
                                final_risks.append(risk)
                                risk_id_counter += 1
                        elif "error" in analysis_json:
                            # Esta es la única salida de error esperada
                            if "No se encontraron marcas de revisión" in analysis_json.get("error", ""):
                                logging.info("Se detectó un lote sin marcas de revisión, se devolverá el error.")
                                if len(results) == 1: # Si es el único lote, devolver error
                                    return {"message": analysis_json["error"]}
                                else: # Si otros lotes sí tienen, solo log
                                    logging.warning(f"Un lote devolvió una nota: {analysis_json['error']}")
                            else:
                                logging.warning(f"Un lote devolvió un error genérico: {analysis_json['error']}")
                    except json.JSONDecodeError as json_err:
                        logging.error(f"Error al decodificar JSON de la API: {json_err}. Respuesta: {analysis_content_str[:200]}...")
        
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error de la API de Azure: {e.response.text}")
        except Exception as e:
            logging.error(f"Error inesperado en análisis: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

    final_response = {"riesgos_identificados": final_risks}
    SESSION_CACHE[session_id]["analysis"] = final_response
    
    return {"raw_analysis": json.dumps(final_response), "session_id": session_id}


# --- (NUEVA) FUNCIÓN DE BATCHING (Reutilizada) ---
def create_batches(image_urls: List[str], knowledge_base_urls: List[str]) -> List[List[str]]:
    """Función auxiliar para crear lotes de imágenes sin exceder el límite."""
    
    global KNOWLEDGE_BASE_SIZE_BYTES
    batches = []
    current_batch_size = KNOWLEDGE_BASE_SIZE_BYTES
    current_batch_images = []
    SAFE_LIMIT_BYTES = SAFE_PAYLOAD_LIMIT_MB * 1024 * 1024
    
    for image_url in image_urls:
        if not image_url: continue # Omitir imágenes fallidas
        image_size = get_base64_size_bytes(image_url)
        
        if image_size + KNOWLEDGE_BASE_SIZE_BYTES > SAFE_LIMIT_BYTES:
            logging.warning(f"Una imagen ({image_size/1024/1024:.2f}MB) es demasiado grande, se omite.")
            continue
        
        if current_batch_size + image_size > SAFE_LIMIT_BYTES and current_batch_images:
            batches.append(current_batch_images)
            current_batch_images = []
            current_batch_size = KNOWLEDGE_BASE_SIZE_BYTES
        
        current_batch_images.append(image_url)
        current_batch_size += image_size
    
    if current_batch_images:
        batches.append(current_batch_images)
    
    return batches


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
    
    # Decidimos qué prompt de sistema usar en el chat.
    system_prompt = PROMPT_CHAT_RIESGOS
    
    messages_for_api = [
        {"role": "system", "content": system_prompt},
        *chat_history_from_client[:-1], 
        {"role": "user", "content": user_multimodal_content}
    ]
    
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


# --- ENDPOINT DE DESCARGA ---
class DownloadRequest(BaseModel):
    session_id: str

@app.post("/download_report")
async def download_report(request: DownloadRequest):
    # ... (Tu código de download_report no cambia) ...
    session_id = request.session_id
    session_data = SESSION_CACHE.get(session_id)

    if not session_data:
        raise HTTPException(status_code=404, detail="Sesión no válida o no encontrada.")
    
    analysis_data = session_data.get("analysis")
    if not analysis_data or "riesgos_identificados" not in analysis_data:
        raise HTTPException(status_code=400, detail="No se encontró un análisis de riesgos en esta sesión para descargar.")
    
    riesgos = analysis_data["riesgos_identificados"]
    
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_ALL)
    
    # Encabezados del CSV (estilo "What If")
    writer.writerow(['ID', 'Riesgo (What If)', 'Consecuencia', 'Mitigaciones Existentes', 'Recomendación Principal', 'Alternativa Práctica'])
    
    for riesgo in riesgos:
        riesgo_id = riesgo.get('id', 'N/A')
        titulo = riesgo.get('riesgo_titulo', 'N/A').replace('\n', ' ')
        descripcion = riesgo.get('descripcion', 'N/A').replace('\n', ' ')
        ubicacion = riesgo.get('ubicacion', 'N/A').replace('\n', ' ')
        causa = riesgo.get('causa_potencial', 'N/A').replace('\n', ' ')
        
        # Procesar la recomendación para dividirla
        recomendacion_full = riesgo.get('recomendacion', 'N/A')
        
        # Función para extraer texto después de un subtítulo
        def extract_text(key, text):
            match = re.search(f"{key}:(.*?)(?=(Mitigaciones Existentes:|Recomendación Principal:|Alternativa Práctica:|$))", text, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip().replace('\n', ' ') if match else 'N/A'

        mitigaciones = extract_text("Mitigaciones Existentes", recomendacion_full)
        rec_principal = extract_text("Recomendación Principal", recomendacion_full)
        alt_practica = extract_text("Alternativa Práctica", recomendacion_full)

        # Crear las columnas 'What If' y 'Consecuencia'
        what_if = f"{titulo} - {descripcion} (Ubicación: {ubicacion})"
        consecuencia = causa
        
        writer.writerow([riesgo_id, what_if, consecuencia, mitigaciones, rec_principal, alt_practica])
        
    csv_data = output.getvalue().encode('utf-8-sig') 
    
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=analisis_de_riesgos_what-if.csv"}
    )
# --- FIN: ENDPOINT DE DESCARGA ---

# --- INICIO: ENDPOINT /rate_analysis (MODIFICADO) ---
@app.post("/rate_analysis")
async def rate_analysis(request: RatingRequest):
    # ... (Tu código de rate_analysis no cambia) ...
    try:
        session_id = request.session_id
        rating = request.rating
        comment = request.comment or ""
        tiempo_ahorrado = request.tiempo_ahorrado or "No especificado"

        if not (1 <= rating <= 5):
            raise HTTPException(status_code=400, detail="La calificación debe estar entre 1 y 5.")
        
        if not STORAGE_ACCOUNT_URL:
            logging.error("STORAGE_ACCOUNT_URL no está configurada.")
            raise HTTPException(status_code=500, detail="La URL de la cuenta de almacenamiento no está configurada.")

        logging.info(f"Recibida calificación para sesión {session_id}: {rating} estrellas, Tiempo: {tiempo_ahorrado}, Comentario: {comment[:20]}...")

        blob_service_client = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=credential)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=BLOB_NAME)

        output = io.StringIO()
        writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_ALL)
        writer.writerow([session_id, rating, comment.replace('\n', ' '), tiempo_ahorrado])
        new_line_data = output.getvalue().encode('utf-8')
        output.close()
        
        header = "session_id;rating;comment;tiempo_ahorrado\n".encode('utf-8')

        if not blob_client.exists():
            logging.info(f"Creando nuevo append blob: {BLOB_NAME} en contenedor: {CONTAINER_NAME}")
            blob_client.create_append_blob() 
            blob_client.append_block(header)

        blob_client.append_block(new_line_data)

        return {"status": "success", "message": "Rating received"}
    
    except Exception as e:
        logging.error(f"Error al guardar la calificación en el blob: {e}")
        raise HTTPException(status_code=500, detail="Error interno al guardar la calificación.")
# --- FIN: ENDPOINT /rate_analysis ---

# --- INICIO: ENDPOINT /get_ratings (MODIFICADO) ---
@app.get("/get_ratings")
async def get_ratings():
    # ... (Tu código de get_ratings no cambia) ...
    if not STORAGE_ACCOUNT_URL:
        logging.error("STORAGE_ACCOUNT_URL no está configurada.")
        raise HTTPException(status_code=500, detail="La URL de la cuenta de almacenamiento no está configurada.")

    ratings = []
    try:
        blob_service_client = BlobServiceClient(account_url=STORAGE_ACCOUNT_URL, credential=credential)
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=BLOB_NAME)

        if not blob_client.exists():
            logging.warning(f"Se solicitó /get_ratings, pero el blob {BLOB_NAME} no existe.")
            return [] 

        downloader = blob_client.download_blob()
        blob_data_bytes = downloader.readall()
        
        blob_data_str = blob_data_bytes.decode('utf-8')
        csv_file = io.StringIO(blob_data_str)
        
        reader = csv.DictReader(csv_file, delimiter=';')
        for row in reader:
            try:
                row['rating'] = int(row['rating'])
                ratings.append(row)
            except (ValueError, KeyError):
                logging.warning(f"Omitiendo fila mal formada en CSV: {row}")
        
        return ratings
    
    except Exception as e:
        logging.error(f"Error al leer el blob de calificaciones: {e}")
        raise HTTPException(status_code=500, detail="Error interno al leer las calificaciones.")
# --- FIN: ENDPOINT /get_ratings ---


@app.get("/")
def read_root():
    return {"message": "API de Análisis de Riesgos está en línea."}