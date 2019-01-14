from conans import ConanFile, AutoToolsBuildEnvironment
import re

class MainProject(ConanFile):
    name = "libethercat"
    license = "GPLv3"
    url = f"https://rmc-github.robotic.dlr.de/common/{name}"
    description = "This library provides all functionality to communicate with EtherCAT slaves attached to a Network interface"
    settings = "os", "compiler", "build_type", "arch"
    scm = {
        "type": "git",
        "url": "auto",
        "revision": "auto",
        "submodule": "recursive",
    }

    generators = "pkg_config"

    def source(self):
        filedata = None
        filename = "project.properties"
        with open(filename, 'r') as f:
            filedata = f.read()
        with open(filename, 'w') as f:
            f.write(re.sub("VERSION *=.*[^\n]", f"VERSION = {self.version}", filedata))

    def build(self):
        self.run("autoreconf -if")
        autotools = AutoToolsBuildEnvironment(self)
        autotools.libs=[]
        autotools.include_paths=[]
        autotools.library_paths=[]
        if self.settings.build_type == "Debug":
            autotools.flags = ["-O0", "-g"]
        else:
            autotools.flags = ["-O2"]
        autotools.configure(configure_dir=".")
        autotools.make()

    def package(self):
        autotools = AutoToolsBuildEnvironment(self)
        autotools.install()

    def package_info(self):
        self.cpp_info.includedirs = ['include']
        self.cpp_info.libs = ["ethercat"]
        self.cpp_info.bindirs = ['bin']
        self.cpp_info.resdirs = ['share']
