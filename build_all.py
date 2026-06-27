import os
import subprocess
import sys
import shutil

# Define the targets (OS, ARCH, extension)
targets = [
    ("linux", "amd64", ""),
    ("linux", "arm64", ""),
    ("darwin", "amd64", ""),
    ("darwin", "arm64", ""),
    ("windows", "amd64", ".exe"),
    ("windows", "arm64", ".exe"),
]

binary_name = "ipscanner"
module_path = "github.com/ehsaanpour/IP-Scanner"
version = "v1.0.0"
commit = "287a08d"
built_by = "manual"

ldflags = f"-s -w -X {module_path}/pkg/version.Version={version} -X {module_path}/pkg/version.Commit={commit} -X {module_path}/pkg/version.BuiltBy={built_by}"

os.makedirs("dist", exist_ok=True)
tmp_dir = os.path.abspath("dist/tmp")
os.makedirs(tmp_dir, exist_ok=True)

print("Starting build for all platforms...")

for os_name, arch, ext in targets:
    output_path = os.path.join("dist", f"{binary_name}-{os_name}-{arch}{ext}")
    print(f"Building {os_name}/{arch} -> {output_path}...")
    
    # Set environment variables
    env = os.environ.copy()
    env["GOOS"] = os_name
    env["GOARCH"] = arch
    env["GOTMPDIR"] = tmp_dir
    
    # Run go build
    cmd = [
        "go", "build",
        "-trimpath",
        "-ldflags", ldflags,
        "-o", output_path,
        "."
    ]
    
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error building {os_name}/{arch}:")
        print(result.stderr)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        sys.exit(1)
    else:
        print(f"Successfully built {output_path}")

# Clean up tmp directory
shutil.rmtree(tmp_dir, ignore_errors=True)
print("All builds completed successfully!")
