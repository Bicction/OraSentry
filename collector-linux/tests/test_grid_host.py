import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_collector import ROOT, BASH


@unittest.skipUnless(BASH, 'bash is not available')
class GridHostTests(unittest.TestCase):
    def collect(self, exists=True, user='root', timeout_rc=0):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            folder=Path(td).relative_to(ROOT).as_posix()
            command=f'''
export PATH=/usr/bin:/bin:$PATH
source lib/host_check.sh
COLLECT_DIR="$PWD"
id() {{
    if [[ "$1" == grid ]]; then return {0 if exists else 1}; fi
    if [[ "$1" == -u ]]; then echo {0 if user=='root' else 1001}; else echo {user}; fi
}}
record_collection() {{ printf '%s|' "$@" >> '{folder}/manifest'; }}
timeout() {{
    if [[ {timeout_rc} -ne 0 ]]; then return {timeout_rc}; fi
    shift 3
    "$@"
}}
su() {{
    printf '%s|' "$@" > '{folder}/su_args'
    cat >/dev/null
    printf 'GRID_USER=grid\\nGRID_COLLECTION=OK\\n'
}}
collect_grid_rac '{folder}'
'''
            result=subprocess.run([BASH,'-c',command],cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            output=(Path(td)/'grid_rac.txt').read_text(encoding='utf-8')
            args=(Path(td)/'su_args').read_text() if (Path(td)/'su_args').exists() else ''
            manifest=(Path(td)/'manifest').read_text(encoding='utf-8')
            return output,args,manifest

    def test_root_uses_grid_login_shell(self):
        output,args,manifest=self.collect()
        self.assertIn('-|grid|-s|/bin/bash|-c|exec /bin/bash -s|',args)
        self.assertIn('GRID_USER=grid',output)
        self.assertIn('|OK|',manifest)

    def test_no_grid_user_is_skipped(self):
        output,args,manifest=self.collect(exists=False)
        self.assertIn('GRID_COLLECTION=SKIPPED',output)
        self.assertFalse(args)
        self.assertIn('|SKIPPED|',manifest)

    def test_unprivileged_collection_never_prompts_for_password(self):
        output,args,manifest=self.collect(user='oracle')
        self.assertIn('GRID_COLLECTION=FAILED',output)
        self.assertFalse(args)
        self.assertIn('|WARN|',manifest)

    def test_switch_timeout_is_recorded(self):
        output,args,manifest=self.collect(timeout_rc=124)
        self.assertIn('GRID_EXIT_CODE=124',output)
        self.assertIn('|WARN|124|',manifest)

    def test_helper_only_issues_read_only_status_commands(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root=Path(td);bin_dir=root/'bin';bin_dir.mkdir()
            log=root/'calls'
            for command in ('crsctl','olsnodes'):
                script=bin_dir/command
                script.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$GRID_TEST_LOG"\necho OK\n',encoding='utf-8',newline='\n')
                script.chmod(0o755)
            relative=root.relative_to(ROOT).as_posix()
            command=f'''
export PATH=/usr/bin:/bin:$PATH
id() {{ echo grid; }}
timeout() {{ shift 3; "$@"; }}
export -f id timeout
export GRID_HOME="$PWD/{relative}"
export GRID_TEST_LOG="$PWD/{relative}/calls"
bash lib/grid_check.sh
'''
            result=subprocess.run([BASH,'-c',command],cwd=ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(log.read_text().splitlines(),['check crs','check cluster -all','stat res -t','-n -s'])
            self.assertIn('GRID_COLLECTION=OK',result.stdout)


if __name__=='__main__': unittest.main()
