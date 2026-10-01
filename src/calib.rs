//! Per-session AFE calibration: carry freshly computed calibration results into
//! the replayed command stream.
//!
//! HP's `scsSensorFalconCalibrate` runs seven sweep steps (CommDet, PgaOffset,
//! Adc, AspLna1, AspPga1, PgaGain, Woe — `capture_seq` idx 6..12). Each step is
//! one sweep frame; the host picks a value from it and writes that value into a
//! calibration-override section of every later `0x02` command. Replaying the
//! recorded stream verbatim feeds the sensor the values chosen on the day of the
//! recording, which drifts the no-finger baseline into the finger range (see
//! NOTES.md 2026-10-01). Only three steps produce values that vary between
//! sessions; this module patches those into the remaining commands.
//!
//! Override entries are `type16 len16 payload` TLVs:
//! - register write: `03 00 09 00 | addr32 | val32 | width(04)`
//! - Adc gain:       `05 00 0e 00 | 14 20 ff ff 00 ff 00 00 00 00 00 00 | adc 00`
//!
//! A calibrated register appears twice in each command that carries it: first
//! in the base table (the fixed sweep default) and again in the override. Only
//! the last occurrence is the override, and only when there are two or more.

/// Register set by the PgaOffset step.
pub const REG_PGA_OFFSET: u32 = 0x3004_20c8;
/// Registers set by the PgaGain step (two channels).
pub const REG_PGA_GAIN: [u32; 2] = [0x3004_2120, 0x3004_2160];

/// Header + fixed payload prefix of the Adc override entry; the Adc value is the
/// byte that follows.
const ADC_ENTRY: [u8; 16] = [
    0x05, 0x00, 0x0e, 0x00, 0x14, 0x20, 0xff, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Offsets of the 32-bit value of every write to `addr` in `cmd`.
fn reg_value_offsets(cmd: &[u8], addr: u32) -> Vec<usize> {
    let mut hdr = vec![0x03, 0x00, 0x09, 0x00];
    hdr.extend_from_slice(&addr.to_le_bytes());
    cmd.windows(hdr.len())
        .enumerate()
        .filter(|(_, w)| *w == hdr.as_slice())
        .map(|(i, _)| i + hdr.len())
        .filter(|&o| o + 4 <= cmd.len())
        .collect()
}

/// Set the override (last of two or more) write to `addr` in `cmd` to `val`.
/// Returns whether an override was present.
pub fn patch_reg(cmd: &mut [u8], addr: u32, val: u32) -> bool {
    let offs = reg_value_offsets(cmd, addr);
    if offs.len() < 2 {
        return false;
    }
    let o = *offs.last().unwrap();
    cmd[o..o + 4].copy_from_slice(&val.to_le_bytes());
    true
}

/// Set every Adc override entry in `cmd` to `adc`. Returns whether any was present.
pub fn patch_adc(cmd: &mut [u8], adc: u8) -> bool {
    let offs: Vec<usize> = cmd
        .windows(ADC_ENTRY.len())
        .enumerate()
        .filter(|(_, w)| *w == ADC_ENTRY)
        .map(|(i, _)| i + ADC_ENTRY.len())
        .filter(|&o| o < cmd.len())
        .collect();
    for &o in &offs {
        cmd[o] = adc;
    }
    !offs.is_empty()
}

/// Every sweep frame is made of 0xd0-byte lines: an 8-byte header (`01 fe`,
/// u16 LE line counter from 1, sweep value at byte 4) then samples; the final
/// line is the `01 01` end marker (its samples still count).
const LINE_LEN: usize = 0xd0;
const LINE_HDR: usize = 8;

/// Why a sweep frame was not used (HP rejects the same frames with error 0x11).
#[derive(Debug, PartialEq, Eq)]
pub enum CalError {
    /// Wrong size for this step's sweep.
    Size(usize),
    /// Line `n`'s header is not `01 fe` with counter `n + 1` — lines were dropped.
    Line(usize),
    /// The last line is not the `01 01` end marker.
    NoEndMarker,
    /// The decision rule found no valid value (HP errors 7/8).
    NoResult,
}

/// Check a sweep frame of `lines` lines the way `scsFalconCalSumLines` does:
/// consecutive line counters and a closing end marker.
pub fn validate(frame: &[u8], lines: usize) -> Result<(), CalError> {
    if frame.len() != lines * LINE_LEN {
        return Err(CalError::Size(frame.len()));
    }
    for n in 0..lines - 1 {
        let h = &frame[n * LINE_LEN..];
        if h[0] != 0x01 || h[1] != 0xfe || u16::from_le_bytes([h[2], h[3]]) as usize != n + 1 {
            return Err(CalError::Line(n));
        }
    }
    let end = &frame[(lines - 1) * LINE_LEN..];
    if end[0] != 0x01 || end[1] != 0x01 {
        return Err(CalError::NoEndMarker);
    }
    Ok(())
}

/// For each sweep value (a group of `per_val` consecutive lines), sum `cols`
/// over the group and split them into the even-offset (A) and odd-offset (B)
/// interleave groups, as HP's steps do with interleave width 1.
fn sweep_sums(
    frame: &[u8],
    per_val: usize,
    cols: std::ops::RangeInclusive<usize>,
) -> Vec<(u32, u32)> {
    let lines = frame.len() / LINE_LEN;
    (0..lines / per_val)
        .map(|g| {
            let (mut a, mut b) = (0u32, 0u32);
            for line in g * per_val..(g + 1) * per_val {
                let row = &frame[line * LINE_LEN + LINE_HDR..(line + 1) * LINE_LEN];
                for (i, c) in cols.clone().enumerate() {
                    if i % 2 == 0 {
                        a += row[c] as u32;
                    } else {
                        b += row[c] as u32;
                    }
                }
            }
            (a, b)
        })
        .collect()
}

/// PgaOffset sweep: 256 lines, one per value 0..=255 of reg 0x300420c8.
const PGA_OFFSET_LINES: usize = 256;
/// Summed columns (`flcn_caled60b0` +4 @0x5e7644: 50..199).
const PGA_OFFSET_COLS: std::ops::RangeInclusive<usize> = 50..=199;

/// Port of `scsFalconCalPgaOffset` @0x50e010: the offset whose line mean is
/// closest to mid-scale 127 (|sum − 127·150| minimal, first wins). HP's limits
/// (0..=30 or 128..=158) only set an error status; the value is used anyway.
/// Verified against 5 HP runs and HP's own 256 internal sums.
pub fn compute_pga_offset(frame: &[u8]) -> Result<u8, CalError> {
    validate(frame, PGA_OFFSET_LINES)?;
    let target = 127 * PGA_OFFSET_COLS.count() as i64;
    let mut best = (i64::MAX, 0xffu8);
    for (v, (a, b)) in sweep_sums(frame, 1, PGA_OFFSET_COLS).into_iter().enumerate() {
        let d = ((a + b) as i64 - target).abs();
        if d < best.0 {
            best = (d, v as u8);
        }
    }
    Ok(best.1)
}

/// Adc sweep: 60 lines, two per value 107..=136 (descriptor @0x5e4f6d).
const ADC_LINES: usize = 0x3c;
const ADC_COLS: std::ops::RangeInclusive<usize> = 0x7d..=0x96;
const ADC_FIRST: u8 = 0x6b;
/// Valid result range (`gCalAdcLimits_116_136_116_136` @0x572324).
pub const ADC_LIMITS: std::ops::RangeInclusive<u8> = 116..=136;

/// Port of `scsFalconCalAdc` @0x50d9e0: the swept value whose A or B column
/// sum is the largest (first strict maximum wins). Verified against 5 HP runs.
pub fn compute_adc(frame: &[u8]) -> Result<u8, CalError> {
    validate(frame, ADC_LINES)?;
    let mut best = (0u32, ADC_FIRST);
    for (k, (a, b)) in sweep_sums(frame, 2, ADC_COLS).into_iter().enumerate() {
        for s in [a, b] {
            if s > best.0 {
                best = (s, ADC_FIRST + k as u8);
            }
        }
    }
    Ok(best.1)
}

/// PgaGain sweep: 32 lines, two per value 0..=15.
const PGA_GAIN_LINES: usize = 32;
/// Summed columns (`flcn_caled5718` @0x5e6d44: 158..187).
const PGA_GAIN_COLS: std::ops::RangeInclusive<usize> = 0x9e..=0xbb;

/// Port of `scsFalconCalPgaGain` @0x50d110. A and B move in opposite directions
/// as gain rises and saturate at the last value. With D = 10 counts/pixel
/// (2 lines × 10 × 15 columns = 300), find the first value whose A is within D
/// of the last value's A; the result is the value BEFORE it (the highest gain
/// not yet near saturation). HP writes the same value to both channel registers.
/// Verified against 5 HP runs and HP's own internal record table.
pub fn compute_pga_gain(frame: &[u8]) -> Result<u8, CalError> {
    validate(frame, PGA_GAIN_LINES)?;
    let recs = sweep_sums(frame, 2, PGA_GAIN_COLS);
    let d = 2 * 10 * (PGA_GAIN_COLS.count() as u32 / 2);
    let (al, bl) = *recs.last().ok_or(CalError::NoResult)?;
    if al == bl {
        return Err(CalError::NoResult);
    }
    // A rises to saturation and B falls (the observed case), or the mirror.
    let rising = al > bl;
    let near_a = |a: u32| if rising { a + d >= al } else { a <= al + d };
    let near_b = |b: u32| if rising { b <= bl + d } else { b + d >= bl };
    let i = recs.iter().position(|&(a, _)| near_a(a)).ok_or(CalError::NoResult)?;
    if !recs.iter().any(|&(_, b)| near_b(b)) {
        return Err(CalError::NoResult);
    }
    Ok(i.saturating_sub(1) as u8)
}

/// `capture_seq` index of each varying step's sweep command.
const SEQ_PGA_OFFSET: usize = 7;
const SEQ_ADC: usize = 8;
const SEQ_PGA_GAIN: usize = 11;

/// After sweep command `idx` returned `frame` (its raw EP2 slice), compute that
/// step's result and write it into every later command (`later` = the commands
/// after `idx`), as HP carries each result into the next step. Steps whose value
/// never varies are left as recorded. On a bad frame the recorded value is kept
/// and a warning logged. Returns a description of what was applied, if any.
pub fn carry_forward(idx: usize, frame: &[u8], later: &mut [Vec<u8>]) -> Option<String> {
    let (name, result) = match idx {
        SEQ_PGA_OFFSET => ("PgaOffset", compute_pga_offset(frame)),
        SEQ_ADC => ("Adc", compute_adc(frame)),
        SEQ_PGA_GAIN => ("PgaGain", compute_pga_gain(frame)),
        _ => return None,
    };
    let v = match result {
        Ok(v) => v,
        Err(e) => {
            log::warn!("calibration {name}: unusable sweep frame ({e:?}); keeping recorded value");
            return None;
        }
    };
    let mut sites = 0;
    for cmd in later.iter_mut() {
        sites += match idx {
            SEQ_PGA_OFFSET => patch_reg(cmd, REG_PGA_OFFSET, v as u32) as usize,
            SEQ_ADC => patch_adc(cmd, v) as usize,
            _ => REG_PGA_GAIN.iter().map(|&r| patch_reg(cmd, r, v as u32) as usize).sum(),
        };
    }
    if idx == SEQ_ADC && !ADC_LIMITS.contains(&v) {
        log::warn!("calibration Adc={v} is outside HP's limits {ADC_LIMITS:?} (HP uses it anyway)");
    }
    Some(format!("{name}={v} ({sites} sites)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HP's own calibration frames + results (local, gitignored device data);
    /// each test is skipped when the frames are not present.
    fn hp_frame(run: u32, name: &str) -> Option<Vec<u8>> {
        std::fs::read(format!("captures/calib_frames/run{run}/{name}.bin")).ok()
    }

    #[test]
    fn adc_matches_hp_ground_truth() {
        for (run, want) in [(1, 130), (2, 129), (3, 133), (4, 133), (5, 129)] {
            let Some(f) = hp_frame(run, "03_Adc") else { return };
            assert_eq!(compute_adc(&f), Ok(want), "run{run}");
        }
    }

    #[test]
    fn pga_offset_matches_hp_ground_truth() {
        for run in 1..=5 {
            let Some(f) = hp_frame(run, "02_PgaOffset") else { return };
            assert_eq!(compute_pga_offset(&f), Ok(5), "run{run}");
        }
    }

    #[test]
    fn pga_gain_matches_hp_ground_truth() {
        for run in 1..=5 {
            let Some(f) = hp_frame(run, "06_PgaGain") else { return };
            assert_eq!(compute_pga_gain(&f), Ok(6), "run{run}");
        }
    }

    #[test]
    fn rejects_frame_with_dropped_lines() {
        let Some(mut f) = hp_frame(1, "06_PgaGain") else { return };
        // Splice out lines 14..=26 the way an EP2 FIFO overflow does.
        f.drain(14 * LINE_LEN..27 * LINE_LEN);
        f.resize(32 * LINE_LEN, 0);
        assert_eq!(compute_pga_gain(&f), Err(CalError::Line(14)));
    }

    fn reg(addr: u32, val: u32) -> Vec<u8> {
        let mut v = vec![0x03, 0x00, 0x09, 0x00];
        v.extend_from_slice(&addr.to_le_bytes());
        v.extend_from_slice(&val.to_le_bytes());
        v.push(0x04);
        v
    }

    #[test]
    fn patches_only_the_override_write() {
        let mut cmd = vec![0x02];
        cmd.extend(reg(REG_PGA_OFFSET, 0)); // base table: sweep default
        cmd.extend(reg(0x3004_2154, 1));
        cmd.extend(reg(REG_PGA_OFFSET, 5)); // override
        assert!(patch_reg(&mut cmd, REG_PGA_OFFSET, 4));
        assert_eq!(reg_value_offsets(&cmd, REG_PGA_OFFSET).len(), 2);
        let o = reg_value_offsets(&cmd, REG_PGA_OFFSET);
        assert_eq!(cmd[o[0]], 0, "base-table default must be untouched");
        assert_eq!(cmd[o[1]], 4);
    }

    #[test]
    fn single_write_is_not_an_override() {
        let mut cmd = vec![0x02];
        cmd.extend(reg(REG_PGA_GAIN[0], 8));
        let before = cmd.clone();
        assert!(!patch_reg(&mut cmd, REG_PGA_GAIN[0], 6));
        assert_eq!(cmd, before);
    }

    #[test]
    fn patches_adc_entry() {
        let mut cmd = vec![0x02, 0x04];
        cmd.extend_from_slice(&ADC_ENTRY);
        cmd.extend_from_slice(&[0x84, 0x00]);
        cmd.extend(reg(REG_PGA_GAIN[0], 7));
        assert!(patch_adc(&mut cmd, 0x81));
        assert_eq!(cmd[2 + ADC_ENTRY.len()], 0x81);
        assert_eq!(cmd[2 + ADC_ENTRY.len() + 1], 0x00);
    }
}
