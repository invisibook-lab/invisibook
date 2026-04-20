use anyhow::{bail, ensure};
use std::{
    env, fs,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{TempDir, tempdir};

/// A handle to a compiled circom circuit, used for testing.
///
/// Compiles circom files and provides witness generation via node.js.
pub struct TestCircuitHandle {
    dir: TempDir,
    /// Name prefix of the compiled circuit (e.g. "circuit" or "main")
    name: String,
}

impl TestCircuitHandle {
    /// Compile a circuit file relative to CARGO_MANIFEST_DIR.
    pub fn new(file_name: &str) -> anyhow::Result<Self> {
        let cargo_manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let src_circuit_path = cargo_manifest_dir.join(file_name);
        let content = fs::read_to_string(&src_circuit_path)?;
        Self::new_from_str(&content)
    }

    /// Compile a circuit from source string.
    pub fn new_from_str(circuit_src: &str) -> anyhow::Result<Self> {
        let dir = tempdir()?;
        let cargo_manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let include_root_dir = cargo_manifest_dir.join("templates");
        let tmp_circuit_path = dir.path().join("circuit.circom");
        let mut tmp_circuit_file = File::create(&tmp_circuit_path)?;
        tmp_circuit_file.write_all(circuit_src.as_bytes())?;

        let output = Command::new("circom")
            .args([
                "--O0",
                "-l",
                include_root_dir.to_str().unwrap(),
                tmp_circuit_path.to_str().unwrap(),
                "--wasm",
                "--r1cs",
                "-o",
                dir.path().to_str().unwrap(),
            ])
            .output()?;

        println!("{}", String::from_utf8_lossy(&output.stdout));
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!("circom compilation failed:\n{}\n{}", stdout, stderr);
        }
        ensure!(output.status.success());
        Ok(Self {
            dir,
            name: "circuit".to_string(),
        })
    }

    /// Create a handle from a pre-compiled circuit output directory.
    /// The directory should contain `<name>.r1cs` and `<name>_js/` with WASM files.
    pub fn from_compiled(compiled_dir: &Path) -> anyhow::Result<Self> {
        // Detect the circuit name by looking for *.r1cs files
        let name = fs::read_dir(compiled_dir)?
            .filter_map(|e| e.ok())
            .find(|e| e.path().extension().map_or(false, |ext| ext == "r1cs"))
            .map(|e| e.path().file_stem().unwrap().to_string_lossy().to_string())
            .ok_or_else(|| anyhow::anyhow!("No .r1cs file found in {:?}", compiled_dir))?;

        // Create a temporary directory that symlinks to the compiled output
        let dir = tempdir()?;
        // Copy the necessary files
        let r1cs_src = compiled_dir.join(format!("{name}.r1cs"));
        let r1cs_dst = dir.path().join(format!("{name}.r1cs"));
        fs::copy(&r1cs_src, &r1cs_dst)?;

        let js_src = compiled_dir.join(format!("{name}_js"));
        let js_dst = dir.path().join(format!("{name}_js"));
        copy_dir_recursive(&js_src, &js_dst)?;

        Ok(Self { dir, name })
    }

    /// Generate a witness from the given input signals JSON.
    /// Returns the path to the generated witness file (`.wtns`).
    pub fn gen_witness(&self, input: &serde_json::Value) -> anyhow::Result<PathBuf> {
        let input_str = serde_json::to_string(input)?;
        let input_file = self.dir.path().join("input.json");
        let witness_file = self.dir.path().join("witness.wtns");
        fs::write(&input_file, input_str.as_bytes())?;

        let output = Command::new("node")
            .args([
                self.witness_gen_js_path().to_str().unwrap(),
                self.witness_gen_wasm_path().to_str().unwrap(),
                input_file.to_str().unwrap(),
                witness_file.to_str().unwrap(),
            ])
            .output()?;

        if output.status.success() {
            Ok(witness_file)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!("Witness generation failed:\n{}\n{}", stdout, stderr)
        }
    }

    /// Path to the compiled R1CS file.
    pub fn r1cs_path(&self) -> PathBuf {
        self.dir.path().join(format!("{}.r1cs", self.name))
    }

    /// Path to the compiled WASM file.
    pub fn wasm_path(&self) -> PathBuf {
        self.dir
            .path()
            .join(format!("{}_js/{}.wasm", self.name, self.name))
    }

    /// Path to the witness generator JS entry point.
    fn witness_gen_js_path(&self) -> PathBuf {
        self.dir
            .path()
            .join(format!("{}_js/generate_witness.js", self.name))
    }

    /// Path to the witness generator WASM binary.
    fn witness_gen_wasm_path(&self) -> PathBuf {
        self.dir
            .path()
            .join(format!("{}_js/{}.wasm", self.name, self.name))
    }
}

/// Recursively copy a directory tree from `src` to `dst`.
fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else {
            fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}
