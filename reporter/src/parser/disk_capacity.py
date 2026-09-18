"""Capacity-aware disk thresholds shared by Linux and Windows reports."""
import math

from config import HOST_THRESHOLDS
from parser.base import check_threshold


def assess_disk_capacity(usage, total_gb, free_gb):
    """Return overall and free-space status, capping GB floors for small volumes."""
    if not all(math.isfinite(v) for v in (usage, total_gb, free_gb)) or total_gb <= 0 or free_gb < 0 or not 0 <= usage <= 100:
        return 'UNKNOWN', 'UNKNOWN'
    warn = HOST_THRESHOLDS['disk_usage_warn']
    crit = HOST_THRESHOLDS['disk_usage_crit']
    free_warn = min(HOST_THRESHOLDS['disk_free_warn'], total_gb * (100-warn)/100)
    free_crit = min(HOST_THRESHOLDS['disk_free_crit'], total_gb * (100-crit)/100)
    free_status = 'CRIT' if free_gb <= free_crit else 'WARN' if free_gb <= free_warn else 'OK'
    status = check_threshold(usage, warn, crit)
    order = {'OK': 0, 'WARN': 1, 'CRIT': 2}
    return max((status, free_status), key=order.get), free_status
