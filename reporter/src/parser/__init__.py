# -*- coding: utf-8 -*-
"""
解析器包 - 解析 Shell 采集的原始数据文件
"""
from parser.base import CheckResult, check_threshold, check_threshold_inverse, generate_bar_chart, generate_data_table

__all__ = ['parse_host', 'parse_db', 'parse_security', 'CheckResult', 'check_threshold', 'check_threshold_inverse', 'generate_bar_chart', 'generate_data_table']


def __getattr__(name):
    """Keep the scoring/UI import of parser.base free of report parsers."""
    modules = {"parse_host": "host_parser", "parse_db": "db_parser", "parse_security": "security_parser"}
    if name not in modules:
        raise AttributeError("module %r has no attribute %r" % (__name__, name))
    from importlib import import_module
    value = getattr(import_module("parser." + modules[name]), name)
    globals()[name] = value
    return value
