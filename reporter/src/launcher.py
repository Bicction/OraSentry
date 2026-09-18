"""Small frozen entry point: keep splash visible through imports and first paint."""
import sys
import startup


def main():
    startup.mark("python_entry")
    startup.connect_splash()
    startup.update_splash("正在准备界面…")
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--verify-package":
            from package_check import verify_package
            return verify_package(sys.argv[2])
        import gui
        startup.mark("gui_imported")
        gui.main()
        return 0
    except Exception:
        import traceback
        detail = traceback.format_exc()
        startup.mark("startup_error", detail=detail)
        startup.close_splash()
        try:
            from tkinter import messagebox
            messagebox.showerror("OraSentry 启动失败", "程序未能完成启动。\n\n" + detail[-2000:])
        except Exception:
            pass
        return 1
    finally:
        startup.close_splash()


if __name__ == "__main__":
    raise SystemExit(main())
