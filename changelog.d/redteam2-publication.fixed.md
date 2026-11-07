- The publication tooling fails closed on five holes the second red team found: `export.py` refuses a target that
  contains the repository or is a non-empty directory that is not the public clone (a wrong target once deleted the
  repository), never touches any `.git`, and refuses symbolic links; private passages are removed whole or the build
  stops; a missing client-names file is an error and an export needs it; a denied term split across a line break is
  caught.
