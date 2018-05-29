from cx_Freeze import setup, Executable


setup(
    name="SOS",
    version="0.1",
    description="Save our secrets",
    executables=[Executable("main.py")],
    options={"build_exe": {"include_msvcr": True}}
)
