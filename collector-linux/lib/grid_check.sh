#!/bin/bash
# Read-only Grid checks, fed to a login shell running as grid by host_check.sh.
export LC_ALL=C
echo "GRID_USER=$(id -un)"
if [[ "$(id -un)" != "grid" ]]; then
    echo 'GRID_COLLECTION=FAILED'
    echo 'GRID_REASON=检查进程未以grid用户运行'
    exit 1
fi
grid_home="${GRID_HOME:-${ORACLE_HOME:-}}"
if [[ ! -x "${grid_home}/bin/crsctl" && -r /etc/oracle/olr.loc ]]; then
    grid_home=$(awk -F= '$1 == "crs_home" {print substr($0,index($0,"=")+1); exit}' /etc/oracle/olr.loc)
fi
crsctl="${grid_home}/bin/crsctl"
if [[ ! -x "${crsctl}" ]]; then
    crsctl=$(command -v crsctl 2>/dev/null)
fi
if [[ ! -x "${crsctl}" ]] || ! command -v timeout >/dev/null 2>&1; then
    echo 'GRID_COLLECTION=FAILED'
    echo 'GRID_REASON=无法定位crsctl或缺少timeout命令，请核实grid环境'
    exit 1
fi
grid_bin=$(dirname "${crsctl}")
echo "GRID_HOME=$(dirname "${grid_bin}")"
run_grid_check() {
    local label="$1"
    shift
    printf '@@BEGIN %s\n' "${label}"
    timeout -k 2s 20s "$@" </dev/null 2>&1
    local rc=$?
    printf '\n@@END %s %s\n' "${label}" "${rc}"
}
run_grid_check crs_check "${crsctl}" check crs
run_grid_check cluster_check "${crsctl}" check cluster -all
run_grid_check resources "${crsctl}" stat res -t
run_grid_check nodes "${grid_bin}/olsnodes" -n -s
echo 'GRID_COLLECTION=OK'
