"""Shared tablespace usage overview for database and container checks.

Capacity values passed to this view are in GB. Invalid or unavailable rows
remain visible in the table, but must not become zero-valued chart entries.
"""
from config import DB_THRESHOLDS
from parser.base import generate_bar_chart, generate_data_table


def effective_usage(ts):
    return ts['max_pct'] if ts['auto'].upper() == 'YES' else ts['alloc_pct']


def render_tablespace_overview(data, *, containers=False):
    ordered = sorted(data, key=lambda ts: (
        ts.get('max_pct') is None,
        -(ts.get('max_pct') or 0),
        ts.get('container', ''), ts['name'], ts.get('con_id', ''),
    ))
    bars, rows = [], []
    for ts in ordered:
        label = (ts['container'] + '/' if containers else '') + ts['name']
        if ts.get('max_pct') is not None:
            bars.append((label, ts.get('chart_pct', effective_usage(ts)), '%'))

        def formatted(key, suffix=''):
            value = ts.get(key)
            return f'{value:.2f}{suffix}' if value is not None else 'N/A'

        row = [ts['name'], ts['contents'], formatted('alloc'), formatted('used'),
               formatted('free'), formatted('alloc_pct', '%'), formatted('max'),
               formatted('max_pct', '%'), ts['auto'], ts['status']]
        if containers:
            row.insert(0, ts['container'])
        rows.append(row)
    headers = ['表空间', '类型', '已分配(GB)', '已用(GB)', '当前空闲(GB)',
               '分配使用率', '最大(GB)', '最大使用率', '自动扩展', '状态']
    if containers:
        headers.insert(0, '容器')
    chart = generate_bar_chart(
        bars, warn_threshold=DB_THRESHOLDS['tablespace_usage_warn'],
        crit_threshold=DB_THRESHOLDS['tablespace_usage_crit'],
    ) if bars else ''
    return chart + generate_data_table(headers, rows)
