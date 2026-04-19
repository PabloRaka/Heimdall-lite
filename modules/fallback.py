from modules.memory import STM, LTM, GM

def _format_decision(status: str, action: str, reason: str, confidence: float, target: str) -> dict:
    """Helper untuk memastikan output JSON Schema-nya selalu konsisten dengan arsitektur"""
    return {
        "status": status,
        "action": action,
        "target": target,
        "reason": reason,
        "confidence": confidence
    }

def rule_based_fallback(event: dict) -> dict:
    """
    "Otak Cadangan" deterministik yang tidak bisa terkena Prompt Injection.
    Dieksekusi JIKA koneksi ke Ollama mati, API timeout, atau LLM mengembalikan error.
    """
    # Ekstrak data dari event log (dict)
    ip = event.get("ip", "")
    path = event.get("path", "")
    username = event.get("username", "")

    # 1. CEK LTM: Whitelist Priority (Highest Priority)
    # Jika ada di whitelist, kebal dari semua deteksi lainnya
    if LTM.is_whitelisted(ip):
        return _format_decision("SAFE", "NONE", "IP terdaftar di whitelist (Trusted Devices)", 1.0, ip)

    # 2. CEK GM: Blacklisted Paths
    if path and GM.is_blacklisted_path(path):
        return _format_decision("THREAT", "BLOCK_CF", f"Mencoba mengakses path terlarang: {path}", 1.0, ip)

    # 3. CEK GM: Forbidden Usernames (Misal mencoba login pakai 'root')
    if username and GM.is_forbidden_user(username):
        return _format_decision("THREAT", "BLOCK_UFW", f"Mencoba login dengan username dilarang: {username}", 0.9, ip)

    # 4. CEK GM & STM: Threshold Brute Force
    stm_context = STM.get(ip)
    if stm_context:
        # Dinamis mengambil threshold dari GM
        rules = GM._get_rules()
        threshold = rules.get("auto_block_threshold", 5)
        
        if stm_context.get("failed_attempts", 0) >= threshold:
            return _format_decision("THREAT", "BLOCK_UFW", f"Threshold brute force ({threshold}x) tercapai", 0.95, ip)

    # 5. Default Fallback (Aktivitas aneh tapi tidak masuk rule mutlak)
    return _format_decision("SUSPICIOUS", "ALERT_ONLY", "Aktivitas tidak dikenali rule statis, butuh review manual", 0.5, ip)
