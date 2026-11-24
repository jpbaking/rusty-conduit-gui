//! A platform-neutral tray image, so each backend can convert it to its own format.

/// An RGBA image, 8 bits per channel, rows top to bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl TrayImage {
    /// Returns `None` unless `rgba` holds exactly `width * height` pixels.
    pub fn new(width: u32, height: u32, rgba: Vec<u8>) -> Option<Self> {
        let pixels = usize::try_from(u64::from(width) * u64::from(height)).ok()?;
        (width > 0 && height > 0 && rgba.len() == pixels.checked_mul(4)?)
            .then_some(Self { width, height, rgba })
    }

    /// ARGB32 in network byte order, as the StatusNotifierItem `IconPixmap` property needs.
    pub fn to_argb32(&self) -> Vec<u8> {
        let (pixels, _) = self.rgba.as_chunks::<4>();
        pixels.iter().flat_map(|&[r, g, b, a]| [a, r, g, b]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_rejects_a_buffer_of_the_wrong_size() {
        assert!(TrayImage::new(2, 1, vec![0; 8]).is_some());
        assert!(TrayImage::new(2, 1, vec![0; 7]).is_none());
        assert!(TrayImage::new(0, 0, Vec::new()).is_none());
    }

    #[test]
    fn image_converts_rgba_to_network_order_argb() {
        let image = TrayImage::new(2, 1, vec![1, 2, 3, 4, 10, 20, 30, 40]).unwrap();
        assert_eq!(image.to_argb32(), vec![4, 1, 2, 3, 40, 10, 20, 30]);
    }
}
