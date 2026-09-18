"""Interpret read-only Grid commands collected by the Linux host workflow."""
import re

from parser.base import CheckResult, read_file, generate_data_table


def parse_grid_status(host_dir):
    title = 'Grid/RAC运行状态'
    text = read_file(f'{host_dir}/grid_rac.txt')
    if not text:
        return CheckResult(title, 'UNKNOWN', '未采集', '采集包缺少主机Grid检查数据',
                           '使用新版主机采集器重新采集')
    meta = dict(re.findall(r'(?m)^(GRID_[A-Z_]+)=(.*)$', text))
    if meta.get('GRID_COLLECTION') == 'SKIPPED':
        return CheckResult(title, 'INFO', '不适用', meta.get('GRID_REASON', '本机未发现grid用户'))
    blocks = {name: (output.strip(), int(rc)) for name, output, rc in re.findall(
        r'@@BEGIN (\w+)\r?\n(.*?)\r?\n@@END \1 (\d+)', text, re.S)}
    names = {'crs_check': 'crsctl check crs', 'cluster_check': 'crsctl check cluster -all',
             'resources': 'crsctl stat res -t', 'nodes': 'olsnodes -n -s'}
    rows = [(label, blocks[name][1], blocks[name][0]) for name, label in names.items() if name in blocks]
    states, notes = [], []
    if meta.get('GRID_USER') != 'grid' or meta.get('GRID_COLLECTION') != 'OK':
        states.append('UNKNOWN')
        notes.append(meta.get('GRID_REASON', 'Grid命令未完整执行或执行用户未确认'))
    for name, label in names.items():
        if name not in blocks or blocks[name][1] != 0 or not blocks[name][0]:
            states.append('UNKNOWN')
            notes.append(label+' 未成功返回完整结果')
    for name, codes in [('crs_check', ('4638','4537','4529','4533')),
                        ('cluster_check', ('4537','4529','4533'))]:
        output = blocks.get(name, ('', 1))[0]
        if re.search(r'CRS-(?:4535|4530|4534|4639)\b|\bis offline\b|\bnot running\b', output, re.I):
            states.append('CRIT'); notes.append(names[name]+' 检测到集群组件离线或无法通信')
        elif not all(re.search(r'CRS-'+code+r':[^\n]*\bonline\b', output, re.I) for code in codes):
            states.append('UNKNOWN')
    resource_states = re.findall(r'(?m)^\s*(?:\d+\s+)?(ONLINE|OFFLINE)\s+(ONLINE|OFFLINE|INTERMEDIATE|UNKNOWN)\b',
                                 blocks.get('resources', ('', 1))[0])
    if not resource_states:
        states.append('UNKNOWN'); notes.append('未识别到资源运行状态')
    for target, actual in resource_states:
        if target == 'ONLINE' and actual == 'OFFLINE':
            states.append('CRIT'); notes.append('存在目标ONLINE但实际OFFLINE的集群资源')
        elif target != actual:
            states.append('WARN'); notes.append('存在资源状态与目标不一致或处于过渡状态')
    if re.search(r'\bInactive\b', blocks.get('nodes', ('', 1))[0], re.I):
        states.append('WARN'); notes.append('存在Inactive集群节点')
    status = next((s for s in ('CRIT','WARN','UNKNOWN') if s in states), 'OK')
    detail = '以grid用户执行只读检查；Grid Home: '+meta.get('GRID_HOME', '未获取')
    detail += f'；识别 {len(resource_states)} 个资源实例；目标OFFLINE且实际OFFLINE不作为故障'
    if notes:
        detail += '；'+'；'.join(dict.fromkeys(notes))
    return CheckResult(title, status, '运行正常' if status=='OK' else '需要核实', detail,
                       '结合命令明细检查集群组件、节点和资源状态；采集器不会启动或停止资源' if status!='OK' else '',
                       generate_data_table(['检查命令','返回码','输出'], rows))
