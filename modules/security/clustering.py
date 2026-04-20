import time
import logging
from collections import defaultdict
from modules.core.memory import STM, LTM

logger = logging.getLogger(__name__)

# Konfigurasi default
CLUSTER_WINDOW_SECONDS = 300    # 5 menit
CLUSTER_MIN_IPS = 3             # Minimal 3 IP berbeda = botnet
CLUSTER_SIMILARITY_PATHS = 2    # Minimal 2 path yang sama


class IPCluster:
    """
    Modul IP Clustering / Botnet Detection.
    Mendeteksi serangan terkoordinasi dari beberapa IP berbeda yang
    menyerang target yang sama dalam waktu berdekatan.
    
    Pattern yang dideteksi:
    - N IP berbeda mengakses path yang sama dalam window X menit
    - N IP berbeda memicu failed login dari service yang sama
    """

    @classmethod
    def detect_botnet(cls) -> dict:
        """
        Menganalisis STM untuk mendeteksi pola serangan botnet.
        Returns: dict berisi is_botnet, cluster_size, shared_paths, ips
        """
        stm_data = STM._read_stm()
        
        if len(stm_data) < CLUSTER_MIN_IPS:
            return {"is_botnet": False, "cluster_size": 0, "clusters": []}

        # Analisis path similarity
        path_to_ips = defaultdict(set)
        now = time.time()

        for ip, data in stm_data.items():
            try:
                last_seen = time.mktime(time.strptime(data["last_seen"], "%Y-%m-%dT%H:%M:%S"))
                if (now - last_seen) > CLUSTER_WINDOW_SECONDS:
                    continue
            except Exception:
                continue

            for path in data.get("paths_accessed", []):
                path_to_ips[path].add(ip)

        # Cari cluster: path yang diakses oleh >= CLUSTER_MIN_IPS IP berbeda
        clusters = []
        botnet_ips = set()

        for path, ips in path_to_ips.items():
            if len(ips) >= CLUSTER_MIN_IPS:
                clusters.append({
                    "path": path,
                    "ips": list(ips),
                    "count": len(ips)
                })
                botnet_ips.update(ips)

        # Analisis service similarity
        service_to_ips = defaultdict(set)
        for ip, data in stm_data.items():
            try:
                last_seen = time.mktime(time.strptime(data["last_seen"], "%Y-%m-%dT%H:%M:%S"))
                if (now - last_seen) > CLUSTER_WINDOW_SECONDS:
                    continue
            except Exception:
                continue

            service = data.get("service", "")
            if service and data.get("failed_attempts", 0) >= 3:
                service_to_ips[service].add(ip)

        for service, ips in service_to_ips.items():
            if len(ips) >= CLUSTER_MIN_IPS:
                clusters.append({
                    "service": service,
                    "ips": list(ips),
                    "count": len(ips)
                })
                botnet_ips.update(ips)

        is_botnet = len(botnet_ips) >= CLUSTER_MIN_IPS

        if is_botnet:
            logger.warning(f"[CLUSTER] 🤖 Botnet terdeteksi! {len(botnet_ips)} IPs dalam {len(clusters)} cluster")

        return {
            "is_botnet": is_botnet,
            "cluster_size": len(botnet_ips),
            "botnet_ips": list(botnet_ips),
            "clusters": clusters
        }

    @classmethod
    def format_report(cls) -> str:
        """Format laporan botnet untuk Telegram"""
        result = cls.detect_botnet()

        if not result["is_botnet"]:
            return "🟢 *Botnet Detection*: Tidak ada serangan terkoordinasi terdeteksi."

        report = [f"🤖 *BOTNET / COORDINATED ATTACK DETECTED*\n"]
        report.append(f"Total IP terlibat: {result['cluster_size']}")
        report.append(f"IPs: {', '.join([f'`{ip}`' for ip in result['botnet_ips'][:15]])}")
        report.append("")

        for i, cluster in enumerate(result["clusters"], 1):
            if "path" in cluster:
                report.append(f"*Cluster {i}* — Path: `{cluster['path']}`")
            elif "service" in cluster:
                report.append(f"*Cluster {i}* — Service: `{cluster['service']}`")
            report.append(f"  IPs ({cluster['count']}): {', '.join([f'`{ip}`' for ip in cluster['ips'][:10]])}")

        return "\n".join(report)


cluster_detector = IPCluster()
