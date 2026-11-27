//! The EDID the guest reads for its one scanout: an EDID 1.4 base block whose
//! preferred detailed timing is the display's mode.

/// The block's length. No extension blocks follow it.
pub const LEN: usize = 128;

const REFRESH_HZ: u64 = 60;
/// CVT reduced blanking: a fixed horizontal blank, and a vertical blank of at
/// least 460 microseconds.
const H_BLANK: u32 = 160;
const H_FRONT: u32 = 48;
const H_SYNC: u32 = 32;
const V_FRONT: u32 = 3;
const V_SYNC: u32 = 6;
const V_BLANK_MIN_US: u64 = 460;
/// The physical size reported, at 96 pixels per inch.
const DPI: u32 = 96;
/// Common modes listed as standard timings at 60 Hz, as width and the aspect
/// ratio code EDID gives them (0 16:10, 1 4:3, 2 5:4, 3 16:9).
const STANDARD_MODES: [(u32, u8); 8] = [
    (1280, 3),
    (1280, 0),
    (1280, 2),
    (1440, 0),
    (1600, 3),
    (1680, 0),
    (1920, 3),
    (1920, 0),
];

/// The EDID of a monitor whose preferred mode is `width` x `height` at 60 Hz.
/// The mode must satisfy [`crate::is_valid_mode`].
pub fn generate(width: u32, height: u32) -> [u8; LEN] {
    let mut edid = [0u8; LEN];
    edid[..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
    // "BRW", five bits a letter.
    let maker =
        (u16::from(b'B' - b'@') << 10) | (u16::from(b'R' - b'@') << 5) | u16::from(b'W' - b'@');
    edid[8..10].copy_from_slice(&maker.to_be_bytes());
    edid[10..12].copy_from_slice(&1u16.to_le_bytes());
    edid[16] = 1;
    edid[17] = (2026 - 1990) as u8;
    edid[18] = 1;
    edid[19] = 4;
    // Digital input.
    edid[20] = 0x80;
    edid[21] = cm(width);
    edid[22] = cm(height);
    // Gamma 2.2.
    edid[23] = 120;
    // sRGB is the default colour space, the first detailed timing is the
    // native mode, and any mode within the range limits is accepted: a
    // resize offers the guest modes this block does not list.
    edid[24] = 0x07;
    edid[25..35].copy_from_slice(&[0xee, 0x91, 0xa3, 0x54, 0x4c, 0x99, 0x26, 0x0f, 0x50, 0x54]);
    // 640x480, 800x600 and 1024x768 at 60 Hz.
    edid[35] = 0x21;
    edid[36] = 0x08;
    for (slot, mode) in edid[38..54].chunks_mut(2).zip(STANDARD_MODES) {
        slot.copy_from_slice(&standard_timing(mode));
    }
    edid[54..72].copy_from_slice(&detailed_timing(width, height));
    edid[72..90].copy_from_slice(&[
        0x00, 0x00, 0x00, 0xfd, 0x00, 24, 75, 30, 160, 66, 0x00, 0x0a, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20,
    ]);
    edid[90..108].copy_from_slice(&text_descriptor(0xfc, b"Burrow"));
    edid[108..126].copy_from_slice(&[0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    edid[127] = checksum(&edid[..127]);
    edid
}

fn standard_timing((width, aspect): (u32, u8)) -> [u8; 2] {
    [
        (width / 8 - 31) as u8,
        (aspect << 6) | (REFRESH_HZ as u8 - 60),
    ]
}

fn cm(pixels: u32) -> u8 {
    u8::try_from(pixels * 254 / (DPI * 100)).unwrap_or(u8::MAX)
}

fn mm(pixels: u32) -> u32 {
    pixels * 254 / (DPI * 10)
}

fn checksum(bytes: &[u8]) -> u8 {
    0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)))
}

fn text_descriptor(tag: u8, text: &[u8]) -> [u8; 18] {
    let mut d = [0x20u8; 18];
    d[..5].copy_from_slice(&[0, 0, 0, tag, 0]);
    d[5..5 + text.len()].copy_from_slice(text);
    d[5 + text.len()] = 0x0a;
    d
}

fn detailed_timing(width: u32, height: u32) -> [u8; 18] {
    let v_blank = u32::try_from(
        (u64::from(height) * V_BLANK_MIN_US * REFRESH_HZ)
            .div_ceil(1_000_000 - V_BLANK_MIN_US * REFRESH_HZ),
    )
    .unwrap_or(u32::MAX)
    .max(V_FRONT + V_SYNC + 6);
    let total = u64::from(width + H_BLANK) * u64::from(height + v_blank);
    let clock_10khz = u16::try_from((total * REFRESH_HZ).div_ceil(10_000)).unwrap_or(u16::MAX);
    let (w_mm, h_mm) = (mm(width), mm(height));
    let mut d = [0u8; 18];
    d[0..2].copy_from_slice(&clock_10khz.to_le_bytes());
    d[2] = width as u8;
    d[3] = H_BLANK as u8;
    d[4] = (((width >> 8) & 0xf) << 4) as u8 | ((H_BLANK >> 8) & 0xf) as u8;
    d[5] = height as u8;
    d[6] = v_blank as u8;
    d[7] = (((height >> 8) & 0xf) << 4) as u8 | ((v_blank >> 8) & 0xf) as u8;
    d[8] = H_FRONT as u8;
    d[9] = H_SYNC as u8;
    d[10] = ((V_FRONT & 0xf) << 4) as u8 | (V_SYNC & 0xf) as u8;
    d[11] = (((H_FRONT >> 8) & 3) << 6) as u8 | (((H_SYNC >> 8) & 3) << 4) as u8;
    d[12] = w_mm as u8;
    d[13] = h_mm as u8;
    d[14] = (((w_mm >> 8) & 0xf) << 4) as u8 | ((h_mm >> 8) & 0xf) as u8;
    // Digital separate sync, horizontal positive and vertical negative, as
    // reduced blanking has them.
    d[17] = 0x1a;
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preferred(edid: &[u8; LEN]) -> (u32, u32) {
        let d = &edid[54..72];
        (
            u32::from(d[2]) | (u32::from(d[4] >> 4) << 8),
            u32::from(d[5]) | (u32::from(d[7] >> 4) << 8),
        )
    }

    #[test]
    fn the_preferred_timing_is_the_mode_and_the_block_sums_to_zero() {
        for (w, h) in [(640, 480), (1280, 800), (1920, 1080), (3840, 2160)] {
            let edid = generate(w, h);
            assert_eq!(&edid[..8], &[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
            assert_eq!(edid.iter().fold(0u8, |s, b| s.wrapping_add(*b)), 0);
            assert_eq!(preferred(&edid), (w, h));
            assert_eq!((edid[18], edid[19]), (1, 4));
            assert_eq!(edid[126], 0);
        }
    }

    #[test]
    fn the_pixel_clock_is_reduced_blanking_at_60hz() {
        let edid = generate(1920, 1080);
        let clock = u32::from(u16::from_le_bytes([edid[54], edid[55]]));
        // CVT-RB 1920x1080@60 is about 138.5 MHz.
        assert!((13_500..=14_200).contains(&clock), "{clock}");
        let max = generate(3840, 2160);
        assert!(u16::from_le_bytes([max[54], max[55]]) < u16::MAX);
    }

    #[test]
    fn common_modes_are_listed_and_others_accepted_by_range() {
        let edid = generate(1280, 800);
        assert_eq!(edid[24] & 1, 1);
        // 1920x1080 at 60 Hz.
        assert!(edid[38..54].chunks(2).any(|t| t == [0xd1, 0xc0]));
        assert_eq!(&edid[72..76], &[0, 0, 0, 0xfd]);
    }

    #[test]
    fn the_monitor_is_named() {
        let edid = generate(1024, 768);
        assert_eq!(&edid[90..95], &[0, 0, 0, 0xfc, 0]);
        assert_eq!(&edid[95..102], b"Burrow\n");
        assert_eq!(&edid[8..10], &[0x0a, 0x57]);
    }
}
