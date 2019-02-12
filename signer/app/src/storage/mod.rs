use std::fs::{create_dir_all, metadata, read, read_dir, set_permissions, File};
use std::io::{Result, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub struct SimpleKeyStorage {
    path: PathBuf,
}

impl SimpleKeyStorage {
    pub fn new(path: PathBuf) -> Result<SimpleKeyStorage> {
        create_dir_all(&path)?;
        let mut perms = metadata(&path)?.permissions();
        perms.set_mode(0o700);
        set_permissions(&path, perms)?;
        Ok(SimpleKeyStorage { path })
    }

    pub fn get_key(&self, key: &str) -> Result<Vec<u8>> {
        let file_path = self.path.join(key);
        read(file_path)
    }

    pub fn write_key(&self, key: String, value: &[u8]) -> Result<()> {
        let mut file = File::create(self.path.join(key))?;
        file.write_all(value)?;
        let mut perms = file.metadata()?.permissions();

        perms.set_readonly(true);
        perms.set_mode(0o400);
        file.set_permissions(perms)
    }

    pub fn list_keys(&self) -> Result<Vec<String>> {
        let dirs = read_dir(&self.path)?;
        let mut res = Vec::new();
        for entry in dirs {
            let e = entry?;
            if let Ok(x) = e.file_name().into_string() {
                res.push(x);
            }
        }
        Ok(res)
    }
}
