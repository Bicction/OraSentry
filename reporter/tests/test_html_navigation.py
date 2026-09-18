from collections import Counter
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from lxml import html
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from parser.base import CheckResult
from report_gen import generate_report, template_path
from summary_gen import SystemSummary, build_summary_model, generate_summary_html


def check_elements(doc):
    return doc.xpath('//*[@id and starts-with(@id, "check-")]')


def sidebar_checks(doc):
    return doc.xpath('//nav//a[contains(concat(" ", @class, " "), " nav-check ")]')


def check_name(element):
    return (element.xpath('./td[1]')[0].text_content() if element.tag == 'tr'
            else element.xpath('.//*[contains(concat(" ", @class, " "), " cc-name ")]')[0].text_content())


class HtmlNavigationTests(unittest.TestCase):
    def render(self, results):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'report.html'
            generate_report(results, {'hostname': 'navigation-test'}, template_path(), str(path))
            return html.fromstring(path.read_text(encoding='utf-8'))

    def assert_links_resolve(self, doc):
        ids = Counter(doc.xpath('//*[@id]/@id'))
        self.assertFalse([key for key, count in ids.items() if count != 1], 'duplicate HTML IDs')
        for link in doc.xpath('//a[starts-with(@href, "#")]'):
            self.assertEqual(ids[link.get('href')[1:]], 1, (link.text_content(), link.get('href')))

    def assert_matching_order(self, doc):
        checks = check_elements(doc)
        links = sidebar_checks(doc)
        self.assertEqual([e.get('id') for e in checks], [e.get('href')[1:] for e in links])
        self.assertEqual([check_name(e) for e in checks], [e.get('title') for e in links])
        toc = doc.xpath('//a[@class="toc-item"]')
        self.assertEqual([e.get('id') for e in checks], [e.get('href')[1:] for e in toc])
        self.assert_links_resolve(doc)

    def test_reported_overview_and_integrity_mismatch(self):
        results = {'db': [CheckResult('采集完整性', 'OK', '', ''), CheckResult('实例状态', 'OK', '', ''),
                          CheckResult('表空间使用概览', 'WARN', '', '')]}
        doc = self.render(results)
        self.assert_matching_order(doc)
        self.assertEqual(check_name(check_elements(doc)[0]), '表空间使用概览')

    def test_all_categories_share_display_order_including_host_cards(self):
        results = {category: [CheckResult('采集完整性', 'OK', '', ''), CheckResult('普通警告', 'WARN', '', ''),
                              CheckResult('资源概览', 'OK', '', ''), CheckResult('严重问题', 'CRIT', '', '')]
                   for category in ('security', 'rac', 'cdb', 'dg', 'db', 'host', 'custom')}
        self.assert_matching_order(self.render(results))

    def test_stable_ties_and_system_log_last(self):
        names = [('正常甲', 'OK'), ('系统日志', 'CRIT'), ('普通信息', 'INFO'), ('严重甲', 'CRIT'),
                 ('严重乙', 'CRIT'), ('数据缺失', 'UNKNOWN'), ('普通警告', 'WARN'), ('资源概览', 'INFO'), ('正常乙', 'OK')]
        doc = self.render({'host': [CheckResult(n, s, '', '') for n, s in names]})
        self.assert_matching_order(doc)
        self.assertEqual([check_name(e) for e in check_elements(doc)],
                         ['资源概览', '数据缺失', '严重甲', '严重乙', '普通警告', '正常甲', '正常乙', '普通信息', '系统日志'])

    def test_same_name_across_categories_has_distinct_destinations(self):
        doc = self.render({c: [CheckResult('采集完整性', 'WARN', c, '')] for c in ('db', 'host', 'security')})
        self.assert_matching_order(doc)

    def test_duplicates_slug_collisions_and_reserved_suffixes_are_unique(self):
        names = ['重复', '重复', 'A/B', 'A B', 'A-B-2', '---', '...']
        doc = self.render({'db': [CheckResult(n, 'WARN', str(i), '') for i, n in enumerate(names)]})
        self.assert_matching_order(doc)
        self.assertEqual(len(check_elements(doc)), len(names))
        targets = {e.get('id'): e for e in check_elements(doc)}
        for link in doc.xpath('//a[@class="action-item"]'):
            target = targets[link.get('href')[1:]]
            value = target.xpath('./td[3]')[0].text_content()
            self.assertIn(': ' + value, link.text_content())

    def test_repeated_same_object_has_two_targets(self):
        check = CheckResult('重复对象', 'WARN', '1', '')
        doc = self.render({'db': [check, check]})
        self.assert_matching_order(doc)
        self.assertEqual(len(check_elements(doc)), 2)

    def test_special_characters_in_names_remain_readable_and_linkable(self):
        names = ['表空间 / PDB', 'A&B <"name">', '磁盘（中文）', '100%检查']
        self.assert_matching_order(self.render({'db': [CheckResult(n, 'OK', '', '') for n in names]}))

    def test_no_actions_has_visible_empty_state_and_no_dead_link(self):
        doc = self.render({'db': [CheckResult('正常项', 'OK', '', '')]})
        self.assert_links_resolve(doc)
        self.assertIn('未发现需要处理的巡检项', doc.get_element_by_id('actions').text_content())

    def test_empty_results_have_valid_overview_contents_and_summary_links(self):
        self.assert_matching_order(self.render({}))
        self.assert_matching_order(self.render({'db': []}))

    def test_severity_sorted_actions_keep_correct_target(self):
        doc = self.render({'db': [CheckResult('资源概览', 'WARN', 'a', ''), CheckResult('严重问题', 'CRIT', 'b', ''),
                                 CheckResult('数据缺失', 'UNKNOWN', 'c', '')]})
        self.assert_matching_order(doc)
        actions = doc.xpath('//a[@class="action-item"]/strong/text()')
        self.assertEqual(actions, ['数据缺失', '严重问题', '资源概览'])

    def test_rendering_does_not_mutate_input_order(self):
        items = [CheckResult('正常项', 'OK', '', ''), CheckResult('严重问题', 'CRIT', '', '')]
        results = {'db': items}
        self.render(results)
        self.assertEqual([e.name for e in items], ['正常项', '严重问题'])

    def test_summary_navigation_and_system_destinations(self):
        systems = [SystemSummary(hostname='db' + str(i), oracle_sid='ORCL', label='db' + str(i),
                                 timestamp='20260915_120000', health_score=100, score_earned=3, score_possible=3)
                   for i in range(2)]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'summary.html'
            generate_summary_html(build_summary_model(systems), str(p))
            doc = html.fromstring(p.read_text(encoding='utf-8'))
        self.assert_links_resolve(doc)
        self.assertEqual([a.get('href')[1:] for a in sidebar_checks(doc)],
                         doc.xpath('//*[starts-with(@id, "sys-")]/@id'))

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for navigation behavior tests')
    def test_navigation_behavior(self):
        script = Path(__file__).with_name('navigation_runtime.js')
        result = subprocess.run([shutil.which('node'), str(script), template_path()], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
