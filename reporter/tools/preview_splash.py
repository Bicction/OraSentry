"""Preview and validate the exact generated Tcl script, without a full rebuild."""
import argparse
from pathlib import Path
import tkinter as tk


def preview(build, seconds):
    root = tk.Tk()
    root.withdraw()
    root.tk.setvar("_image_data", (build / "startup-assets/splash.png").read_bytes())
    root.tk.eval((build / "AnimatedSplash-00_script.tcl").read_text(encoding="utf-8"))
    root.deiconify()
    def check_animation():
        first = root.tk.getvar("orasentry_angle")
        def again():
            second = root.tk.getvar("orasentry_angle")
            if first == second:
                raise RuntimeError("Splash spinner did not advance")
            print("Splash animation OK:", first, "->", second, flush=True)
        root.after(160, again)
    root.after(100, check_animation)
    root.after(int(seconds * 1000), root.destroy)
    root.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=Path(__file__).resolve().parents[1] / "build/oracle_report")
    parser.add_argument("--seconds", type=float, default=10)
    args = parser.parse_args()
    preview(args.build, args.seconds)
