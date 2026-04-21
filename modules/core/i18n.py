import json
import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOCALES_DIR = BASE_DIR / "locales"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "security_archive.db"

DEFAULT_LANG = "en"

SUPPORTED_LANGUAGES = {
    "en": {"name": "English",          "flag": "🇬🇧", "label": "🇬🇧 English"},
    "id": {"name": "Bahasa Indonesia",  "flag": "🇮🇩", "label": "🇮🇩 Bahasa Indonesia"},
    "zh": {"name": "中文",              "flag": "🇨🇳", "label": "🇨🇳 中文"},
}


class I18n:
    """
    Singleton modul lokalisasi (i18n) untuk Heimdall-lite.

    - Membaca preferensi bahasa dari tabel `settings` di SQLite.
    - Memuat file JSON dari folder locales/.
    - Menyediakan fungsi t(key, **kwargs) sebagai pengganti string hardcoded.
    - Fallback otomatis ke bahasa Inggris jika kunci tidak ditemukan.
    """

    def __init__(self):
        self._lang: str = DEFAULT_LANG
        self._strings: dict = {}
        self._fallback: dict = {}
        self._load_fallback()
        self._load_from_db()

    # ─────────────────────────────────────────────
    # INTERNAL LOADERS
    # ─────────────────────────────────────────────

    def _load_file(self, lang_code: str) -> dict:
        """Muat file JSON locale. Return dict kosong jika tidak ditemukan."""
        path = LOCALES_DIR / f"{lang_code}.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Hapus _meta dari strings
            data.pop("_meta", None)
            return data
        except FileNotFoundError:
            logger.warning(f"[I18N] Locale file not found: {path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"[I18N] Invalid JSON in {path}: {e}")
            return {}

    def _load_fallback(self):
        """Muat fallback (English) ke memori."""
        self._fallback = self._load_file(DEFAULT_LANG)

    def _load_from_db(self):
        """
        Baca preferensi bahasa dari DB.
        Jika tabel `settings` belum ada, pakai default.
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = 'language'")
            row = cursor.fetchone()
            conn.close()

            lang = row[0] if row else DEFAULT_LANG
            self._apply_language(lang)

        except Exception as e:
            logger.warning(f"[I18N] Tidak bisa membaca DB settings: {e}. Pakai default '{DEFAULT_LANG}'.")
            self._apply_language(DEFAULT_LANG)

    def _apply_language(self, lang_code: str):
        """Validasi dan terapkan bahasa. Fallback ke 'en' jika tidak dikenal."""
        if lang_code not in SUPPORTED_LANGUAGES:
            logger.warning(f"[I18N] Lang '{lang_code}' tidak dikenal, fallback ke '{DEFAULT_LANG}'.")
            lang_code = DEFAULT_LANG

        self._lang = lang_code
        if lang_code == DEFAULT_LANG:
            self._strings = self._fallback
        else:
            self._strings = self._load_file(lang_code)

        logger.info(f"[I18N] Bahasa aktif: {lang_code} ({SUPPORTED_LANGUAGES[lang_code]['name']})")

    # ─────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────

    def t(self, key: str, **kwargs) -> str:
        """
        Ambil string berdasarkan key, lakukan format substitusi.
        Fallback ke English jika key tidak ada di bahasa aktif.
        Fallback ke key itu sendiri jika tidak ada di mana pun.

        Contoh:
            i18n.t("intel_title", ip="1.2.3.4")
        """
        # Cari di bahasa aktif dulu
        template = self._strings.get(key)

        # Fallback ke English
        if template is None and self._lang != DEFAULT_LANG:
            template = self._fallback.get(key)
            if template is not None:
                logger.debug(f"[I18N] Key '{key}' tidak ada di '{self._lang}', pakai fallback 'en'.")

        # Fallback terakhir: kembalikan key itu sendiri
        if template is None:
            logger.warning(f"[I18N] Key '{key}' tidak ditemukan di locale manapun.")
            return key

        # Format substitusi jika ada kwargs
        try:
            return template.format(**kwargs) if kwargs else template
        except KeyError as e:
            logger.warning(f"[I18N] Format error pada key '{key}': missing {e}")
            return template

    def set_language(self, lang_code: str) -> bool:
        """
        Simpan bahasa baru ke DB dan terapkan ke runtime.
        Return True jika berhasil.
        """
        if lang_code not in SUPPORTED_LANGUAGES:
            return False

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('language', ?)",
                (lang_code,)
            )
            conn.commit()
            conn.close()

            self._apply_language(lang_code)
            logger.info(f"[I18N] Bahasa diubah ke: {lang_code}")
            return True

        except Exception as e:
            logger.error(f"[I18N] Gagal menyimpan bahasa ke DB: {e}")
            return False

    def get_current_lang(self) -> str:
        """Kembalikan kode bahasa aktif saat ini."""
        return self._lang

    def get_language_name(self) -> str:
        """
        Kembalikan nama bahasa dalam format yang bisa diinjeksikan ke LLM prompt.
        Contoh: "English", "Indonesian", "Chinese (Simplified)"
        """
        names = {
            "en": "English",
            "id": "Indonesian",
            "zh": "Chinese (Simplified)",
        }
        return names.get(self._lang, "English")

    def is_current(self, lang_code: str) -> bool:
        """Cek apakah kode bahasa sama dengan yang aktif."""
        return self._lang == lang_code


# Singleton Instance
i18n = I18n()
