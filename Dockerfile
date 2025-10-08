# Usa una imagen base de Python oficial y ligera
FROM python:3.9-slim

# Instala las dependencias del sistema necesarias para PyMuPDF y renderizado de fuentes/gráficos
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libfontconfig1 \
    libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia primero el archivo de dependencias para aprovechar el caché de Docker
COPY requirements.txt .

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de tu aplicación al contenedor
COPY . .

# Expone el puerto en el que se ejecutará la aplicación
EXPOSE 8000

# Define el comando para iniciar la aplicación cuando el contenedor se ejecute
CMD ["uvicorn", "function_app:app", "--host", "0.0.0.0", "--port", "8000"]