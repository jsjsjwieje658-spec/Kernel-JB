#!/usr/bin/env python3
"""Add DORootHideManager.h/.m to the Dopamine Xcode project (project.pbxproj).

Inserts the two files into the 4 required sections with fresh UUIDs that are
guaranteed not to collide with existing ones:
  1. PBXBuildFile            (DORootHideManager.m in Sources)
  2. PBXFileReference        (.m and .h)
  3. PBXGroup children       (the Settings group, next to DOSettingsController.m)
  4. PBXSourcesBuildPhase    (files list)

Idempotent: skips if DORootHideManager is already referenced.
"""
import re
import sys

PBXPROJ = "/home/z/Kernel-JB/Application/Dopamine.xcodeproj/project.pbxproj"

def main():
    with open(PBXPROJ, "r", encoding="utf-8") as f:
        content = f.read()

    if "DORootHideManager" in content:
        print("SKIP: DORootHideManager already referenced in project.pbxproj")
        return 0

    # Collect existing 24-hex-char object IDs to guarantee uniqueness
    existing_ids = set(re.findall(r"\b([0-9A-F]{24})\b", content))
    print(f"Found {len(existing_ids)} existing object IDs")

    def new_id(seed_label):
        base = "D0D0D0D0D0D0D0D0D0D0D0"
        counter = 0
        while True:
            candidate = f"{base}{counter:02X}"
            candidate = (candidate + "0" * 24)[:24]
            if candidate not in existing_ids:
                existing_ids.add(candidate)
                print(f"  new ID for {seed_label}: {candidate}")
                return candidate
            counter += 1

    id_m_build = new_id("DORootHideManager.m (build file)")
    id_m_ref   = new_id("DORootHideManager.m (file ref)")
    id_h_ref   = new_id("DORootHideManager.h (file ref)")

    # --- 1. PBXBuildFile section ---
    m = re.search(r"/\* Begin PBXBuildFile section \*/\n(.*?)/\* End PBXBuildFile section \*/\n",
                  content, re.DOTALL)
    if not m:
        print("ERROR: PBXBuildFile section not found"); return 1
    buildfile_section = m.group(1)
    buildfile_line = ("\t\t{id} /* DORootHideManager.m in Sources */ = "
                      "{{isa = PBXBuildFile; fileRef = {ref} /* DORootHideManager.m */; }};\n"
                      ).format(id=id_m_build, ref=id_m_ref)
    content = content.replace(buildfile_section, buildfile_section + buildfile_line, 1)

    # --- 2. PBXFileReference section ---
    m = re.search(r"/\* Begin PBXFileReference section \*/\n(.*?)/\* End PBXFileReference section \*/\n",
                  content, re.DOTALL)
    if not m:
        print("ERROR: PBXFileReference section not found"); return 1
    fileref_section = m.group(1)
    fileref_lines = (
        "\t\t{id_h} /* DORootHideManager.h */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.h; path = DORootHideManager.h; sourceTree = \"<group>\"; }};\n"
        "\t\t{id_m} /* DORootHideManager.m */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.objc; path = DORootHideManager.m; sourceTree = \"<group>\"; }};\n"
    ).format(id_h=id_h_ref, id_m=id_m_ref)
    content = content.replace(fileref_section, fileref_section + fileref_lines, 1)

    # --- 3. PBXGroup children (Settings group, anchored on DOSettingsController.h) ---
    m = re.search(r"(\t\t\t\t[0-9A-F]{24} /\* DOSettingsController\.h \*/,\n)", content)
    if not m:
        print("ERROR: DOSettingsController.h group entry not found"); return 1
    anchor = m.group(1)
    group_lines = (
        "\t\t\t\t{id_h} /* DORootHideManager.h */,\n"
        "\t\t\t\t{id_m} /* DORootHideManager.m */,\n"
    ).format(id_h=id_h_ref, id_m=id_m_ref)
    content = content.replace(anchor, anchor + group_lines, 1)

    # --- 4. PBXSourcesBuildPhase files list ---
    m = re.search(r"(\t\t\t\t[0-9A-F]{24} /\* DOSettingsController\.m in Sources \*/,\n)", content)
    if not m:
        print("ERROR: DOSettingsController.m in Sources entry not found"); return 1
    anchor = m.group(1)
    sources_line = "\t\t\t\t{id} /* DORootHideManager.m in Sources */,\n".format(id=id_m_build)
    content = content.replace(anchor, anchor + sources_line, 1)

    with open(PBXPROJ, "w", encoding="utf-8") as f:
        f.write(content)

    print("OK: DORootHideManager.h/.m added to project.pbxproj")
    return 0

if __name__ == "__main__":
    sys.exit(main())
