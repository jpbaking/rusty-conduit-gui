//! Port forward presets: app-wide templates for a session's `-L` / `-R` forwards.

use conduit_core::{validate_forward_preset, ForwardPreset};
use uuid::Uuid;

use super::{AppController, AppError};

impl AppController {
    pub fn list_forward_presets(&self) -> Vec<ForwardPreset> {
        self.config_snapshot().forward_presets
    }

    /// Saves a preset. A nil id is assigned here. Sessions keep the forwards they already have.
    pub fn upsert_forward_preset(&self, mut preset: ForwardPreset) -> Result<ForwardPreset, AppError> {
        if preset.id.is_nil() {
            preset.id = Uuid::new_v4();
        }
        preset.name = preset.name.trim().to_string();
        preset.dest_host = preset.dest_host.trim().to_string();
        validate_forward_preset(&preset).map_err(|e| AppError::Invalid(format!("preset: {e}")))?;
        let saved = preset.clone();
        self.mutate_config(|config| {
            match config.forward_presets.iter_mut().find(|p| p.id == preset.id) {
                Some(existing) => *existing = preset,
                None => config.forward_presets.push(preset),
            }
            Ok(())
        })?;
        Ok(saved)
    }

    pub fn delete_forward_preset(&self, id: Uuid) -> Result<(), AppError> {
        self.mutate_config(|config| {
            let before = config.forward_presets.len();
            config.forward_presets.retain(|p| p.id != id);
            if config.forward_presets.len() == before {
                return Err(AppError::NotFound { kind: "forward preset", id: id.to_string() });
            }
            Ok(())
        })
    }

    /// Adds back any built-in preset that was deleted, and returns the whole list.
    pub fn restore_forward_presets(&self) -> Result<Vec<ForwardPreset>, AppError> {
        self.mutate_config(|config| {
            config.restore_forward_presets();
            Ok(config.forward_presets.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use conduit_core::ForwardDirection;

    fn preset(name: &str) -> ForwardPreset {
        ForwardPreset {
            id: Uuid::nil(),
            name: name.into(),
            direction: ForwardDirection::Local,
            bind: None,
            port: 15000,
            dest_host: String::new(),
            dest_port: 5000,
        }
    }

    #[tokio::test]
    async fn presets_start_with_the_built_ins_and_can_be_edited() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let builtins = c.list_forward_presets();
        assert!(!builtins.is_empty());

        let saved = c.upsert_forward_preset(preset("  Mine  ")).unwrap();
        assert!(!saved.id.is_nil());
        assert_eq!(saved.name, "Mine");
        assert_eq!(c.list_forward_presets().len(), builtins.len() + 1);

        let mut bad = preset("x");
        bad.port = 0;
        assert!(matches!(c.upsert_forward_preset(bad), Err(AppError::Invalid(_))));

        c.delete_forward_preset(builtins[0].id).unwrap();
        c.delete_forward_preset(saved.id).unwrap();
        assert!(matches!(c.delete_forward_preset(saved.id), Err(AppError::NotFound { .. })));
        assert_eq!(c.restore_forward_presets().unwrap().len(), builtins.len());
    }

    #[tokio::test]
    async fn a_deleted_built_in_stays_deleted_after_reopening() {
        let dir = TempDir::new();
        let c = controller(&dir);
        let first = c.list_forward_presets()[0].id;
        c.delete_forward_preset(first).unwrap();
        drop(c);
        let reopened = controller(&dir);
        assert!(!reopened.list_forward_presets().iter().any(|p| p.id == first));
    }
}
