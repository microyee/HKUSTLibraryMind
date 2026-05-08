"""
config.py – loads .env and exposes typed settings
"""
import os
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FLASK_SECRET_KEY    = os.getenv("FLASK_SECRET_KEY", "changeme")

# LLM provider selection: "replicate" (default) or "deepseek"
LLM_PROVIDER        = os.getenv("LLM_PROVIDER", "replicate")

# Replicate
REPLICATE_API_TOKEN = os.getenv("REPLICATE_API_TOKEN", "")
REPLICATE_MODEL     = os.getenv("REPLICATE_MODEL", "meta/meta-llama-3-8b-instruct")

# DeepSeek
DEEPSEEK_API_KEY    = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL   = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")

AGENT_ROUTING_KEY   = os.getenv("AGENT_ROUTING_KEY", "lib-routing-2026-4e8a2f1c")
CHROMA_PERSIST_DIR  = os.getenv("CHROMA_PERSIST_DIR", "./chroma_data")
DATABASE_PATH       = os.getenv("DATABASE_PATH", "./database/library.db")
RESEARCH_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RESEARCH_RATE_LIMIT_MAX_REQUESTS", "8"))
RESEARCH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RESEARCH_RATE_LIMIT_WINDOW_SECONDS", "10"))

FLAG1 = os.getenv("FLAG1", "flag{4g3nt_trust_n0_s1gn4tur3_ch3ck}")
FLAG2 = os.getenv("FLAG2", "flag{cr0ss_s3ss10n_m3m0ry_l34k_adm1n_gh0st}")
FLAG3 = os.getenv("FLAG3", "flag{m3m0ry_p01s0n_turn3d_sup3rv1s0r_1nt0_4tt4ck3r}")

VOW_HIDDEN_FLAG_VIRTUAL_PATH = os.getenv("VOW_HIDDEN_FLAG_VIRTUAL_PATH", "/VowHiddenFlag.txt")
VOW_HIDDEN_FLAG_FILE = os.getenv(
	"VOW_HIDDEN_FLAG_FILE",
	os.path.join(PROJECT_ROOT, "VowHiddenFlag.txt"),
)
