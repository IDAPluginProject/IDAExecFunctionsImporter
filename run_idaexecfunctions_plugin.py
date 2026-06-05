import ida_auto
import ida_loader
import ida_pro


def main():
    ida_auto.auto_wait()
    result = ida_loader.load_and_run_plugin("IDAExecFunctions64", 0)
    print(f"RUN_IDAEXECFUNCTIONS_PLUGIN_RESULT={int(bool(result))}")
    ida_auto.auto_wait()
    ida_pro.qexit(0 if result else 1)


main()
