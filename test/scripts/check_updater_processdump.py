#!/usr/bin/env python3
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Check the installed processdump variants and updater ELF dependency closure."""

import argparse
import collections
import json
from pathlib import Path
import re
import subprocess
import sys


FORBIDDEN_DIRECT_DEPS = (
    "libappexecfwk_", "libipc_", "libsamgr_proxy", "libstack_printer",
    "libhisysevent", "libhitrace",
)


def needed_libraries(binary, readelf):
    result = subprocess.run(
        [readelf, "-d", str(binary)], check=True, capture_output=True, text=True)
    return re.findall(r"\(NEEDED\).*?\[(.*?)\]", result.stdout)


def elf_identity(binary):
    with binary.open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:4] != b"\x7fELF":
        return None
    return header[4:6], header[18:20]


def check_installation(build_dir):
    metadata_dir = build_dir / "obj/base/hiviewdfx/faultloggerd/tools/process_dump"
    system_info = json.loads((metadata_dir / "processdump_module_info.json").read_text())
    if not system_info["install_enable"] or system_info["dest"] != ["system/bin/processdump"]:
        raise ValueError("The system processdump must not also install into updater")
    updater_info = json.loads(
        (metadata_dir / "update_processdump_install_module_info.json").read_text())
    if not updater_info["install_enable"] or updater_info["dest"] != ["updater/bin/processdump"]:
        raise ValueError("The updater installation path must remain updater/bin/processdump")
    system_binary = build_dir / system_info["source"]
    updater_binary = build_dir / updater_info["source"]
    if system_binary.resolve() == updater_binary.resolve():
        raise ValueError("System and updater must have separate build outputs")
    if system_binary.read_bytes() == updater_binary.read_bytes():
        raise ValueError("Updater must not install the full system binary")
    raw_info = json.loads((metadata_dir / "update_processdump_module_info.json").read_text())
    if raw_info["install_enable"]:
        raise ValueError("The internal update_processdump name must not be installed")
    if updater_binary.read_bytes() != (build_dir / raw_info["source"]).read_bytes():
        raise ValueError("Updater must install the output of update_processdump")
    return updater_binary


def check_dependencies(binary, updater_root, readelf):
    direct_deps = needed_libraries(binary, readelf)
    forbidden = [name for name in direct_deps if name.startswith(FORBIDDEN_DIRECT_DEPS)]
    if forbidden:
        raise ValueError("Unexpected updater dependencies: " + ", ".join(forbidden))
    libraries = {}
    identity = elf_identity(binary)
    for dirname in ("lib", "lib64"):
        for path in (updater_root / dirname).rglob("*"):
            if path.is_file() and elf_identity(path) == identity:
                libraries.setdefault(path.name, path)
    queue = collections.deque([(binary, ["processdump"])])
    visited = set()
    missing = []
    while queue:
        path, chain = queue.popleft()
        if path in visited:
            continue
        visited.add(path)
        for name in needed_libraries(path, readelf):
            if name not in libraries:
                missing.append(" -> ".join(chain + [name]))
            else:
                queue.append((libraries[name], chain + [name]))
    if missing:
        raise ValueError("Libraries absent from updater:\n" + "\n".join(missing))
    print(f"PASS: independent installation; {len(direct_deps)} direct dependencies; "
          f"{len(visited)} ELF files in the updater dependency closure")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--updater-root", required=True, type=Path)
    parser.add_argument("--readelf", default="readelf")
    args = parser.parse_args()
    try:
        binary = check_installation(args.build_dir)
        check_dependencies(binary, args.updater_root, args.readelf)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
