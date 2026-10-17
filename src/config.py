import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Configuración de Gemini
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

# Configuración de Batfish
BATFISH_HOST = os.getenv("BATFISH_HOST", "localhost")
BATFISH_PORT = int(os.getenv("BATFISH_PORT", "9997"))

# Rutas estándar del proyecto
REPORTS_DIR = BASE_DIR / "reports"
SKILLS_DIR = BASE_DIR / "skills" / "cisco-security-advisor"
SNAPSHOTS_DIR = BASE_DIR / "snapshots"
CACHE_DIR = BASE_DIR / ".cache"

# Asegurar directorios mínimos
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)
