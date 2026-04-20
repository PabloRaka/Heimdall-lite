import os
import json
import requests
import logging
from dotenv import load_dotenv
from pathlib import Path

# Setup paths & env
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    filename=BASE_DIR / "logs/agent.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "minimax-m1:cloud")
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")

# Import modul internal
from modules.sanitizer import build_prompt
from modules.memory import STM, LTM
from modules.fallback import rule_based_fallback

class Brain:
    """
    Modul Analisis Utama (AI-Driven).
    Menghubungkan Sensor -> Memory -> Sanitizer -> LLM.
    Menerapkan pola 'Fail-Secure' dengan fallback ke rule-based engine.
    """

    @staticmethod
    def _call_llm(prompt: str) -> str:
        """Berkomunikasi dengan LLM menggunakan format OpenAI-Compatible API"""
        url = f"{OLLAMA_BASE_URL.rstrip('/')}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        
        if OLLAMA_API_KEY:
            headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"
            
        payload = {
            "model": OLLAMA_MODEL,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a network security analyzer. Always output valid JSON only, without markdown formatting or preamble."
                },
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1 # Suhu sangat rendah agar output konsisten
        }
        
        # Timeout krusial! (Fail-fast agar tidak membuat bottleneck pada log processing)
        res = requests.post(url, json=payload, headers=headers, timeout=15)
        res.raise_for_status()
        
        return res.json()["choices"][0]["message"]["content"]

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Mengekstrak JSON dengan aman, mentolerir sisa markdown ```json jika model membangkang"""
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Mencoba mengekstrak blok yang diawali { dan diakhiri }
            if "{" in text and "}" in text:
                start = text.find("{")
                end = text.rfind("}") + 1
                return json.loads(text[start:end])
            raise ValueError("Tidak ditemukan format JSON di dalam respons LLM.")

    @staticmethod
    def analyze(event: dict) -> dict:
        """
        Entry point utama untuk menganalisis suatu event.
        Returns dictionary berformat konvensi Micro-SOC.
        """
        ip = event.get("ip")
        if not ip:
            return {"status": "SAFE", "action": "NONE", "target": "unknown", "reason": "No IP specified", "confidence": 1.0}

        # 1. Gather Context (Kumpulkan ingatan tentang IP ini)
        stm_context = STM.get(ip) or {}
        ltm_context = LTM.get_incident_history(ip)
        is_fp = LTM.is_false_positive(ip)

        # 2. Sanitasi & Rakit Prompt
        raw_log = event.get("raw_log", str(event))
        prompt = build_prompt(raw_log, stm_context, ltm_context, is_false_positive=is_fp)

        # 3. Eksekusi LLM (dengan Safety Net)
        try:
            logging.info(f"[BRAIN] Menghubungi LLM untuk menganalisis {ip}...")
            llm_output = Brain._call_llm(prompt)
            
            # 4. Parse output
            decision = Brain._extract_json(llm_output)
            
            # Validasi fields wajib
            required_keys = {"status", "confidence", "action", "target", "reason"}
            if not required_keys.issubset(decision.keys()):
                raise ValueError(f"JSON dari LLM tidak memiliki keys yang lengkap: {decision.keys()}")
                
            confidence = float(decision.get("confidence", 0.0))
            if confidence < 0.6 and decision.get("action") in ["BLOCK_CF", "BLOCK_UFW"]:
                logging.warning(f"[BRAIN] Confidence terlalu rendah ({confidence}), turun ke ALERT_ONLY")
                decision["action"] = "ALERT_ONLY"
                decision["reason"] += f" [Confidence rendah: {confidence}, perlu konfirmasi admin]"

            logging.info(f"[BRAIN] Analisis LLM sukses (Confidence: {decision['confidence']}) -> {decision['action']}")
            return decision

        except Exception as e:
            # Apapun errornya (Timeout, 500 Server Error, JSON Decode Failed, Format Salah)
            # Kita langsung lemparkan ke Fallback Engine yang deterministik.
            logging.warning(f"[BRAIN] ⚠️ AI Analysis gagal ({e}). Jatuh ke Fallback Engine...")
            return rule_based_fallback(event)

# Singleton Instance
brain = Brain()
